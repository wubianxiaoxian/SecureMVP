import Foundation
import CommonCrypto
import CryptoKit
import Security

/// Enterprise-grade PIN authentication manager
/// - PBKDF2-HMAC-SHA256 with 310,000 iterations (OWASP 2023 recommendation)
/// - Constant-time comparison to prevent timing attacks
/// - Secure PIN storage (hash + salt in Keychain)
/// - Integration with Secure Enclave for KEK decryption
class PINManager {

    // MARK: - Error Types

    enum PINError: LocalizedError {
        case pinTooShort
        case pinTooLong
        case pinNotSet
        case pinVerificationFailed
        case derivationFailed
        case saveFailed
        case invalidPIN

        var errorDescription: String? {
            switch self {
            case .pinTooShort:
                return "PIN must be at least 4 digits"
            case .pinTooLong:
                return "PIN must be at most 12 digits"
            case .pinNotSet:
                return "PIN has not been set up"
            case .pinVerificationFailed:
                return "Incorrect PIN"
            case .derivationFailed:
                return "Failed to derive key from PIN"
            case .saveFailed:
                return "Failed to save PIN to Keychain"
            case .invalidPIN:
                return "PIN must contain only digits"
            }
        }
    }

    // MARK: - Constants

    /// PBKDF2 iteration count (OWASP 2023: 310,000 for PBKDF2-HMAC-SHA256)
    private static let pbkdf2Iterations: UInt32 = 310_000

    /// Derived key length (32 bytes = 256 bits for AES-256)
    private static let derivedKeyLength = 32

    /// Salt length (16 bytes = 128 bits)
    private static let saltLength = 16

    /// Minimum PIN length
    private static let minPINLength = 4

    /// Maximum PIN length
    private static let maxPINLength = 12

    // MARK: - Singleton

    static let shared = PINManager()
    private init() {}

    // MARK: - Properties

    private let keychain = KeychainManager.shared

    // MARK: - Public Interface

    /// Check if PIN is set up
    func isPINSet() -> Bool {
        return keychain.exists(type: .userPreferences, account: "pin-hash")
    }

    /// Set up new PIN
    /// - Parameter pin: Numeric PIN (4-12 digits)
    /// - Throws: PINError if validation or save fails
    func setupPIN(_ pin: String) throws {
        print("🔐 Setting up PIN...")

        // Validate PIN
        try validatePIN(pin)

        // Generate random salt
        let salt = generateSalt()

        // Derive hash from PIN using PBKDF2
        let pinHash = try derivePINHash(from: pin, salt: salt)

        // Save hash and salt to Keychain
        let pinData = PINData(hash: pinHash, salt: salt, iterations: Self.pbkdf2Iterations)
        try keychain.save(pinData, type: .userPreferences, account: "pin-hash", accessLevel: .standard)

        print("✅ PIN set up successfully")
    }

    /// Verify PIN
    /// - Parameter pin: PIN to verify
    /// - Returns: true if PIN matches
    /// - Throws: PINError if verification fails
    func verifyPIN(_ pin: String) throws -> Bool {
        print("🔐 Verifying PIN...")

        guard isPINSet() else {
            throw PINError.pinNotSet
        }

        // Load stored PIN data
        let pinData = try keychain.retrieve(type: .userPreferences, account: "pin-hash", as: PINData.self)

        // Derive hash from entered PIN using stored salt
        let enteredPINHash = try derivePINHash(from: pin, salt: pinData.salt, iterations: pinData.iterations)

        // Constant-time comparison to prevent timing attacks
        let isValid = constantTimeCompare(enteredPINHash, pinData.hash)

        if isValid {
            print("✅ PIN verified successfully")
        } else {
            print("❌ PIN verification failed")
            throw PINError.pinVerificationFailed
        }

        return isValid
    }

    /// Derive encryption key from PIN
    /// Used to decrypt KEK from Keychain
    /// - Parameter pin: User's PIN
    /// - Returns: 256-bit symmetric key
    /// - Throws: PINError if derivation fails
    func derivePINKey(from pin: String) throws -> SymmetricKey {
        print("🔐 Deriving encryption key from PIN...")

        guard isPINSet() else {
            throw PINError.pinNotSet
        }

        // First verify PIN is correct
        guard try verifyPIN(pin) else {
            throw PINError.pinVerificationFailed
        }

        // Load stored PIN data
        let pinData = try keychain.retrieve(type: .userPreferences, account: "pin-hash", as: PINData.self)

        // Derive key using same parameters
        let keyData = try deriveKey(from: pin, salt: pinData.salt, iterations: pinData.iterations, keyLength: Self.derivedKeyLength)

        print("✅ Encryption key derived from PIN")
        return SymmetricKey(data: keyData)
    }

    /// Change PIN
    /// - Parameters:
    ///   - oldPIN: Current PIN
    ///   - newPIN: New PIN
    /// - Throws: PINError if verification or save fails
    func changePIN(oldPIN: String, newPIN: String) throws {
        print("🔐 Changing PIN...")

        // Verify old PIN
        guard try verifyPIN(oldPIN) else {
            throw PINError.pinVerificationFailed
        }

        // Validate new PIN
        try validatePIN(newPIN)

        // Set up new PIN (overwrites old one)
        try setupPIN(newPIN)

        print("✅ PIN changed successfully")
    }

    /// Remove PIN
    /// - Throws: KeychainError if deletion fails
    func removePIN() throws {
        print("🔐 Removing PIN...")
        try keychain.delete(type: .userPreferences, account: "pin-hash")
        print("✅ PIN removed successfully")
    }

    // MARK: - Private Helpers

    /// Validate PIN format
    private func validatePIN(_ pin: String) throws {
        // Check length
        guard pin.count >= Self.minPINLength else {
            throw PINError.pinTooShort
        }

        guard pin.count <= Self.maxPINLength else {
            throw PINError.pinTooLong
        }

        // Check that PIN contains only digits
        guard pin.allSatisfy({ $0.isNumber }) else {
            throw PINError.invalidPIN
        }
    }

    /// Derive PIN hash using PBKDF2
    private func derivePINHash(from pin: String, salt: Data, iterations: UInt32 = pbkdf2Iterations) throws -> Data {
        return try deriveKey(from: pin, salt: salt, iterations: iterations, keyLength: Self.derivedKeyLength)
    }

    /// Derive key using PBKDF2-HMAC-SHA256
    /// - Parameters:
    ///   - pin: Input PIN
    ///   - salt: Random salt
    ///   - iterations: Number of PBKDF2 iterations
    ///   - keyLength: Desired key length in bytes
    /// - Returns: Derived key data
    private func deriveKey(from pin: String, salt: Data, iterations: UInt32, keyLength: Int) throws -> Data {
        guard let pinData = pin.data(using: .utf8) else {
            throw PINError.derivationFailed
        }

        var derivedKeyData = Data(count: keyLength)
        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                pinData.withUnsafeBytes { pinBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pinBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        pinData.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }

        guard result == kCCSuccess else {
            throw PINError.derivationFailed
        }

        return derivedKeyData
    }

    /// Generate cryptographically secure random salt
    private func generateSalt() -> Data {
        var salt = Data(count: Self.saltLength)
        _ = salt.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, Self.saltLength, bytes.baseAddress!)
        }
        return salt
    }

    /// Constant-time comparison to prevent timing attacks
    /// - Parameters:
    ///   - lhs: Left-hand side data
    ///   - rhs: Right-hand side data
    /// - Returns: true if data is equal
    private func constantTimeCompare(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }

        var result: UInt8 = 0
        for i in 0..<lhs.count {
            result |= lhs[i] ^ rhs[i]
        }

        return result == 0
    }
}

// MARK: - Data Models

/// PIN storage data
private struct PINData: Codable {
    let hash: Data          // PBKDF2-derived hash
    let salt: Data          // Random salt
    let iterations: UInt32  // PBKDF2 iteration count
    let createdAt: Date
    let version: Int        // PIN data format version

    init(hash: Data, salt: Data, iterations: UInt32) {
        self.hash = hash
        self.salt = salt
        self.iterations = iterations
        self.createdAt = Date()
        self.version = 1
    }
}

// MARK: - Extensions

extension PINManager {

    /// Get PIN strength estimate
    /// - Parameter pin: PIN to evaluate
    /// - Returns: Strength level
    func estimatePINStrength(_ pin: String) -> PINStrength {
        let length = pin.count

        // Check for simple patterns
        let hasRepeatingDigits = Set(pin).count == 1  // e.g., "1111"
        let isSequential = isSequentialPattern(pin)   // e.g., "1234"

        if hasRepeatingDigits || isSequential {
            return .veryWeak
        }

        if length < 6 {
            return .weak
        } else if length < 8 {
            return .medium
        } else if length < 10 {
            return .strong
        } else {
            return .veryStrong
        }
    }

    private func isSequentialPattern(_ pin: String) -> Bool {
        guard pin.count > 1 else { return false }

        let digits = pin.compactMap { Int(String($0)) }
        guard digits.count == pin.count else { return false }

        // Check ascending sequence
        var isAscending = true
        for i in 1..<digits.count {
            if digits[i] != digits[i-1] + 1 {
                isAscending = false
                break
            }
        }

        // Check descending sequence
        var isDescending = true
        for i in 1..<digits.count {
            if digits[i] != digits[i-1] - 1 {
                isDescending = false
                break
            }
        }

        return isAscending || isDescending
    }
}

/// PIN strength levels
enum PINStrength {
    case veryWeak    // Repeating or sequential
    case weak        // 4-5 digits
    case medium      // 6-7 digits
    case strong      // 8-9 digits
    case veryStrong  // 10+ digits

    var description: String {
        switch self {
        case .veryWeak: return "Very Weak"
        case .weak: return "Weak"
        case .medium: return "Medium"
        case .strong: return "Strong"
        case .veryStrong: return "Very Strong"
        }
    }

    var emoji: String {
        switch self {
        case .veryWeak: return "🔴"
        case .weak: return "🟠"
        case .medium: return "🟡"
        case .strong: return "🟢"
        case .veryStrong: return "🔵"
        }
    }
}
