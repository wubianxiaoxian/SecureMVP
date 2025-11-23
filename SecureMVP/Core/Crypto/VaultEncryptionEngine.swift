import Foundation
import CryptoKit

/// Industrial-grade AES-256-GCM encryption engine
/// - AEAD (Authenticated Encryption with Associated Data)
/// - Unique nonce per encryption (CSPRNG)
/// - Multi-layer integrity verification
/// - Cryptographically secure by design
class VaultEncryptionEngine {

    // MARK: - Error Types

    enum EncryptionError: LocalizedError {
        case invalidKeySize
        case encryptionFailed(Error)
        case decryptionFailed(Error)
        case integrityViolation
        case invalidNonceSize
        case invalidCiphertext
        case aadMismatch

        var errorDescription: String? {
            switch self {
            case .invalidKeySize:
                return "Encryption key must be 256 bits (32 bytes)"
            case .encryptionFailed(let error):
                return "Encryption failed: \(error.localizedDescription)"
            case .decryptionFailed(let error):
                return "Decryption failed: \(error.localizedDescription)"
            case .integrityViolation:
                return "Integrity verification failed - data may be tampered"
            case .invalidNonceSize:
                return "Nonce must be 96 bits (12 bytes) for GCM"
            case .invalidCiphertext:
                return "Ciphertext is malformed or corrupted"
            case .aadMismatch:
                return "Associated authenticated data mismatch"
            }
        }
    }

    // MARK: - Constants

    private static let nonceSize = 12 // 96 bits (recommended for GCM)
    private static let keySize = 32   // 256 bits
    private static let tagSize = 16   // 128 bits (GCM authentication tag)

    // MARK: - Encryption Result

    /// Encrypted payload with all necessary components for decryption and verification
    struct EncryptedPayload: Codable {
        /// 96-bit nonce (unique per encryption)
        let nonce: Data

        /// AES-256-GCM ciphertext
        let ciphertext: Data

        /// 128-bit GCM authentication tag (AEAD integrity)
        let tag: Data

        /// Associated Authenticated Data (metadata)
        let aad: Data

        /// Vault version at time of encryption
        let vaultVersion: Int

        /// SHA-256 integrity hash (second layer)
        /// Hash(nonce || ciphertext || tag || aad || vaultVersion)
        let integrityHash: Data

        /// Timestamp of encryption
        let timestamp: Date

        /// Encryption algorithm identifier
        let algorithm: String = "AES-256-GCM"

        /// Computed size of encrypted payload
        var totalSize: Int {
            return nonce.count + ciphertext.count + tag.count + aad.count + integrityHash.count
        }
    }

    // MARK: - Public Interface

    /// Encrypt data using AES-256-GCM with AEAD
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - key: 256-bit AES key (CDK)
    ///   - associatedData: Metadata to authenticate (username, domain, etc.)
    ///   - vaultVersion: Current vault version
    /// - Returns: Encrypted payload with integrity protection
    /// - Throws: EncryptionError if encryption fails
    static func encrypt(
        _ plaintext: Data,
        using key: SymmetricKey,
        associatedData: Data,
        vaultVersion: Int
    ) throws -> EncryptedPayload {

        // Validate key size
        guard key.bitCount == Self.keySize * 8 else {
            throw EncryptionError.invalidKeySize
        }

        // Generate cryptographically secure random nonce (96 bits)
        let nonce = try generateNonce()

        // Perform AES-256-GCM encryption
        let gcmNonce = try AES.GCM.Nonce(data: nonce)

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: gcmNonce,
                authenticating: associatedData // AEAD: authenticate metadata
            )
        } catch {
            throw EncryptionError.encryptionFailed(error)
        }

        // Extract ciphertext and tag from sealed box
        let ciphertext = sealedBox.ciphertext
        let tag = sealedBox.tag

        // Compute second-layer integrity hash (SHA-256)
        let integrityHash = computeIntegrityHash(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
            aad: associatedData,
            vaultVersion: vaultVersion
        )

        // Construct encrypted payload
        return EncryptedPayload(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
            aad: associatedData,
            vaultVersion: vaultVersion,
            integrityHash: integrityHash,
            timestamp: Date()
        )
    }

    /// Decrypt and verify AES-256-GCM encrypted payload
    /// - Parameters:
    ///   - payload: Encrypted payload to decrypt
    ///   - key: 256-bit AES key (must match encryption key)
    /// - Returns: Decrypted plaintext
    /// - Throws: EncryptionError if decryption or verification fails
    static func decrypt(
        _ payload: EncryptedPayload,
        using key: SymmetricKey
    ) throws -> Data {

        // Validate key size
        guard key.bitCount == Self.keySize * 8 else {
            throw EncryptionError.invalidKeySize
        }

        // ========================================
        // LAYER 1: Verify structural integrity hash (SHA-256)
        // ========================================
        let expectedIntegrityHash = computeIntegrityHash(
            nonce: payload.nonce,
            ciphertext: payload.ciphertext,
            tag: payload.tag,
            aad: payload.aad,
            vaultVersion: payload.vaultVersion
        )

        guard expectedIntegrityHash == payload.integrityHash else {
            // CRITICAL: Integrity violation detected!
            logIntegrityViolation(payload: payload)
            throw EncryptionError.integrityViolation
        }

        // ========================================
        // LAYER 2: GCM authentication tag verification (automatic)
        // ========================================
        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: payload.nonce)
        } catch {
            throw EncryptionError.invalidNonceSize
        }

        // Reconstruct sealed box
        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(
                nonce: gcmNonce,
                ciphertext: payload.ciphertext,
                tag: payload.tag
            )
        } catch {
            throw EncryptionError.invalidCiphertext
        }

        // Decrypt and verify GCM tag
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                sealedBox,
                using: key,
                authenticating: payload.aad // Verify AAD matches
            )
        } catch CryptoKitError.authenticationFailure {
            // GCM tag verification failed - data tampered!
            logIntegrityViolation(payload: payload)
            throw EncryptionError.integrityViolation
        } catch {
            throw EncryptionError.decryptionFailed(error)
        }

        return plaintext
    }

    // MARK: - Key Derivation

    /// Derive a 256-bit AES key using HKDF-SHA256
    /// Used to derive CDK from KEK with version-specific salt
    /// - Parameters:
    ///   - kek: Key Encryption Key (master secret)
    ///   - salt: Cryptographic salt (unique per vault version)
    ///   - info: Context/domain separation string
    ///   - outputByteCount: Desired key size (default 32 bytes = 256 bits)
    /// - Returns: Derived symmetric key
    static func deriveKey(
        from kek: SymmetricKey,
        salt: Data,
        info: String,
        outputByteCount: Int = 32
    ) -> SymmetricKey {

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: kek,
            salt: salt,
            info: Data(info.utf8),
            outputByteCount: outputByteCount
        )

        return derivedKey
    }

    /// Generate a cryptographically secure random salt
    /// - Parameter size: Size in bytes (default 32)
    /// - Returns: Random salt data
    static func generateSalt(size: Int = 32) throws -> Data {
        var salt = Data(count: size)
        let result = salt.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, size, ptr.baseAddress!)
        }

        guard result == errSecSuccess else {
            throw EncryptionError.encryptionFailed(
                NSError(domain: "CryptoRNG", code: Int(result),
                       userInfo: [NSLocalizedDescriptionKey: "Failed to generate random salt"])
            )
        }

        return salt
    }

    // MARK: - Nonce Generation

    /// Generate a cryptographically secure random 96-bit nonce
    /// CRITICAL: Must be unique for each encryption with the same key
    /// - Returns: 12-byte nonce
    private static func generateNonce() throws -> Data {
        var nonce = Data(count: Self.nonceSize)
        let result = nonce.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, Self.nonceSize, ptr.baseAddress!)
        }

        guard result == errSecSuccess else {
            throw EncryptionError.encryptionFailed(
                NSError(domain: "CryptoRNG", code: Int(result),
                       userInfo: [NSLocalizedDescriptionKey: "Failed to generate nonce"])
            )
        }

        return nonce
    }

    // MARK: - Integrity Verification

    /// Compute SHA-256 integrity hash over entire encrypted structure
    /// Provides second layer of integrity protection beyond GCM tag
    /// - Parameters:
    ///   - nonce: Encryption nonce
    ///   - ciphertext: Encrypted data
    ///   - tag: GCM authentication tag
    ///   - aad: Associated authenticated data
    ///   - vaultVersion: Vault version number
    /// - Returns: 32-byte SHA-256 hash
    private static func computeIntegrityHash(
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        aad: Data,
        vaultVersion: Int
    ) -> Data {

        var hasher = SHA256()

        // Hash all components in a specific order
        hasher.update(data: nonce)
        hasher.update(data: ciphertext)
        hasher.update(data: tag)
        hasher.update(data: aad)

        // Include vault version as big-endian 64-bit integer
        var versionBytes = vaultVersion.bigEndian
        hasher.update(data: Data(bytes: &versionBytes, count: MemoryLayout<Int>.size))

        let digest = hasher.finalize()
        return Data(digest)
    }

    // MARK: - Security Logging

    /// Log integrity violations for security monitoring
    private static func logIntegrityViolation(payload: EncryptedPayload) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let logEntry = """
        ⚠️ SECURITY ALERT: Integrity Violation Detected
        Timestamp: \(timestamp)
        Vault Version: \(payload.vaultVersion)
        Payload Timestamp: \(payload.timestamp)
        Ciphertext Size: \(payload.ciphertext.count) bytes
        AAD Size: \(payload.aad.count) bytes
        """

        #if DEBUG
        print(logEntry)
        #endif

        // TODO: In production, write to secure audit log and potentially:
        // 1. Increment failed decryption counter
        // 2. Trigger security lockdown after threshold
        // 3. Alert user of potential attack
    }
}

// MARK: - Utility Extensions

extension VaultEncryptionEngine {

    /// Create a new 256-bit symmetric key from raw data
    /// - Parameter data: 32-byte raw key material
    /// - Returns: SymmetricKey instance
    /// - Throws: EncryptionError if data size is invalid
    static func createKey(from data: Data) throws -> SymmetricKey {
        guard data.count == Self.keySize else {
            throw EncryptionError.invalidKeySize
        }
        return SymmetricKey(data: data)
    }

    /// Generate a new random 256-bit symmetric key
    /// - Returns: New SymmetricKey
    static func generateRandomKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }

    /// Securely wipe key material from memory (best effort)
    /// Note: Swift doesn't guarantee memory zeroing, but we try
    static func securelyWipe(_ data: inout Data) {
        data.resetBytes(in: 0..<data.count)
        data.removeAll()
    }
}

// MARK: - AAD (Associated Authenticated Data) Builder

extension VaultEncryptionEngine {

    /// Build AAD from credential metadata
    /// AAD is authenticated but not encrypted - protects against tampering
    static func buildAAD(
        username: String,
        domain: String,
        credentialID: UUID,
        vaultVersion: Int
    ) -> Data {
        let aadString = "\(domain)||\(username)||\(credentialID.uuidString)||\(vaultVersion)"
        return Data(aadString.utf8)
    }

    /// Parse AAD back to components (for verification)
    static func parseAAD(_ aad: Data) -> (username: String, domain: String, credentialID: UUID, vaultVersion: Int)? {
        guard let aadString = String(data: aad, encoding: .utf8) else {
            return nil
        }

        let components = aadString.split(separator: "|").map(String.init)
        guard components.count >= 4,
              let uuid = UUID(uuidString: components[2]),
              let version = Int(components[3]) else {
            return nil
        }

        return (username: components[1], domain: components[0], credentialID: uuid, vaultVersion: version)
    }
}
