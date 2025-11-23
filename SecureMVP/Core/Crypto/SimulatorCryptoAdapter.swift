import Foundation
import CryptoKit

/// Simulator adapter for crypto operations
/// Provides fallback encryption when Secure Enclave is not available
/// ⚠️ WARNING: This is ONLY for testing in simulator - NOT production!
class SimulatorCryptoAdapter {

    // MARK: - Singleton

    static let shared = SimulatorCryptoAdapter()
    private init() {}

    // MARK: - Simulator KEK Storage

    private let simulatorKEKKey = "com.securemvp.simulator.kek"

    /// Generate or retrieve a simulated KEK
    /// Uses Keychain without Secure Enclave protection
    func getSimulatorKEK() throws -> SymmetricKey {
        // Try to retrieve existing KEK
        if let existingKEK = try? retrieveSimulatorKEK() {
            return existingKEK
        }

        // Generate new KEK
        let newKEK = SymmetricKey(size: .bits256)
        try saveSimulatorKEK(newKEK)
        return newKEK
    }

    /// Encrypt data using simulator KEK (instead of Secure Enclave)
    func encryptWithSimulatorKEK(_ data: Data) throws -> Data {
        let kek = try getSimulatorKEK()

        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(data, using: kek, nonce: nonce)

        // Combine nonce + ciphertext + tag
        var combined = Data()
        combined.append(sealedBox.nonce.withUnsafeBytes { Data($0) })
        combined.append(sealedBox.ciphertext)
        combined.append(sealedBox.tag)

        return combined
    }

    /// Decrypt data using simulator KEK
    func decryptWithSimulatorKEK(_ encryptedData: Data) throws -> Data {
        guard encryptedData.count >= 28 else { // 12 (nonce) + 16 (tag)
            throw SimulatorCryptoError.invalidCiphertext
        }

        // Split nonce + ciphertext + tag
        let nonceData = encryptedData.prefix(12)
        let tag = encryptedData.suffix(16)
        let ciphertext = encryptedData.dropFirst(12).dropLast(16)

        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)

        let kek = try getSimulatorKEK()
        let plaintext = try AES.GCM.open(sealedBox, using: kek)

        return plaintext
    }

    // MARK: - Private Storage

    private func saveSimulatorKEK(_ kek: SymmetricKey) throws {
        let kekData = kek.withUnsafeBytes { Data($0) }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: simulatorKEKKey,
            kSecValueData as String: kekData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete existing
        SecItemDelete(query as CFDictionary)

        // Add new
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SimulatorCryptoError.storageFailed(status)
        }
    }

    private func retrieveSimulatorKEK() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: simulatorKEKKey,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            throw SimulatorCryptoError.notFound
        }

        guard let kekData = item as? Data else {
            throw SimulatorCryptoError.invalidData
        }

        return SymmetricKey(data: kekData)
    }

    /// Delete simulator KEK
    func deleteSimulatorKEK() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: simulatorKEKKey
        ]

        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Error Types

    enum SimulatorCryptoError: LocalizedError {
        case notFound
        case invalidData
        case invalidCiphertext
        case storageFailed(OSStatus)

        var errorDescription: String? {
            switch self {
            case .notFound:
                return "Simulator KEK not found"
            case .invalidData:
                return "Invalid key data"
            case .invalidCiphertext:
                return "Invalid ciphertext format"
            case .storageFailed(let status):
                return "Failed to store KEK: \(status)"
            }
        }
    }
}

// MARK: - Debug Helpers

extension SimulatorCryptoAdapter {

    /// Check if running in simulator
    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    /// Print warning about simulator usage
    static func warnSimulatorUsage() {
        #if targetEnvironment(simulator)
        print("""
        ⚠️ WARNING: Running in SIMULATOR mode
        - Secure Enclave is NOT available
        - Using software-based encryption fallback
        - DO NOT use for production testing
        - Test on physical device for real security
        """)
        #endif
    }
}
