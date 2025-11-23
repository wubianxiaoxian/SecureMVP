import Foundation
import Security
import CryptoKit
import LocalAuthentication

/// Manages the Master KEK (Key Encryption Key) stored in Secure Enclave
/// - Hardware-backed P-256 private key
/// - Non-extractable, device-bound
/// - Biometric-protected access
/// - Used to encrypt/decrypt Vault KEK
class SecureEnclaveManager {

    // MARK: - Error Types

    enum SecureEnclaveError: LocalizedError {
        case secureEnclaveNotAvailable
        case keyGenerationFailed(OSStatus)
        case keyNotFound
        case encryptionFailed(Error)
        case decryptionFailed(Error)
        case biometricAuthenticationFailed
        case invalidKeyData

        var errorDescription: String? {
            switch self {
            case .secureEnclaveNotAvailable:
                return "Secure Enclave is not available on this device"
            case .keyGenerationFailed(let status):
                return "Failed to generate Secure Enclave key: \(status)"
            case .keyNotFound:
                return "Secure Enclave master key not found in Keychain"
            case .encryptionFailed(let error):
                return "Encryption failed: \(error.localizedDescription)"
            case .decryptionFailed(let error):
                return "Decryption failed: \(error.localizedDescription)"
            case .biometricAuthenticationFailed:
                return "Biometric authentication failed"
            case .invalidKeyData:
                return "Invalid key data provided"
            }
        }
    }

    // MARK: - Constants

    private static let masterKeyTag = "com.securemvp.masterkey.secureenclave"
    private static let keyLabel = "SecureMVP Master KEK"

    // MARK: - Singleton

    static let shared = SecureEnclaveManager()
    private init() {}

    // MARK: - Public Interface

    /// Check if Secure Enclave is available on this device
    func isSecureEnclaveAvailable() -> Bool {
        #if targetEnvironment(simulator)
        // Secure Enclave is NOT available in simulator
        return false
        #else
        return SecureEnclave.isAvailable
        #endif
    }

    /// Generate or retrieve the Master KEK from Secure Enclave
    /// - Returns: Reference to the private key stored in Secure Enclave
    /// - Throws: SecureEnclaveError if generation/retrieval fails
    func getMasterKey() throws -> SecKey {
        // First, try to retrieve existing key
        if let existingKey = try? retrieveMasterKey() {
            return existingKey
        }

        // If no key exists, generate a new one
        return try generateMasterKey()
    }

    /// Encrypt data using the Secure Enclave master key
    /// - Parameter data: Data to encrypt (typically the Vault KEK)
    /// - Returns: Encrypted data
    /// - Throws: SecureEnclaveError if encryption fails
    func encrypt(_ data: Data) throws -> Data {
        // SIMULATOR FALLBACK
        #if targetEnvironment(simulator)
        SimulatorCryptoAdapter.warnSimulatorUsage()
        return try SimulatorCryptoAdapter.shared.encryptWithSimulatorKEK(data)
        #else

        guard isSecureEnclaveAvailable() else {
            throw SecureEnclaveError.secureEnclaveNotAvailable
        }

        let privateKey = try getMasterKey()

        // Get the public key from the private key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.keyNotFound
        }

        // Encrypt using ECIES (Elliptic Curve Integrated Encryption Scheme)
        // This is the recommended algorithm for P-256 keys
        let algorithm = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw SecureEnclaveError.encryptionFailed(
                NSError(domain: "SecureEnclave", code: -1,
                       userInfo: [NSLocalizedDescriptionKey: "Algorithm not supported"])
            )
        }

        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            data as CFData,
            &error
        ) as Data? else {
            throw SecureEnclaveError.encryptionFailed(error!.takeRetainedValue() as Error)
        }

        return ciphertext
        #endif
    }

    /// Decrypt data using the Secure Enclave master key
    /// - Parameter encryptedData: Data to decrypt
    /// - Parameter context: Optional LAContext for biometric authentication
    /// - Returns: Decrypted data
    /// - Throws: SecureEnclaveError if decryption fails
    func decrypt(_ encryptedData: Data, context: LAContext? = nil) throws -> Data {
        // SIMULATOR FALLBACK
        #if targetEnvironment(simulator)
        return try SimulatorCryptoAdapter.shared.decryptWithSimulatorKEK(encryptedData)
        #else

        guard isSecureEnclaveAvailable() else {
            throw SecureEnclaveError.secureEnclaveNotAvailable
        }

        let privateKey = try retrieveMasterKey(context: context)

        let algorithm = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM

        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw SecureEnclaveError.decryptionFailed(
                NSError(domain: "SecureEnclave", code: -1,
                       userInfo: [NSLocalizedDescriptionKey: "Algorithm not supported"])
            )
        }

        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey,
            algorithm,
            encryptedData as CFData,
            &error
        ) as Data? else {
            throw SecureEnclaveError.decryptionFailed(error!.takeRetainedValue() as Error)
        }

        return plaintext
        #endif
    }

    /// Delete the master key from Secure Enclave and Keychain
    /// ⚠️ WARNING: This will make all encrypted data unrecoverable!
    func deleteMasterKey() throws {
        #if targetEnvironment(simulator)
        SimulatorCryptoAdapter.shared.deleteSimulatorKEK()
        return
        #else

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.masterKeyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveError.keyGenerationFailed(status)
        }
        #endif
    }

    // MARK: - Private Helpers

    /// Generate a new P-256 private key in Secure Enclave
    private func generateMasterKey() throws -> SecKey {
        guard isSecureEnclaveAvailable() else {
            throw SecureEnclaveError.secureEnclaveNotAvailable
        }

        // Create access control: biometric or device passcode required
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny], // Allow Face ID or Touch ID
            nil
        ) else {
            throw SecureEnclaveError.keyGenerationFailed(errSecAllocate)
        }

        // Key generation parameters
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256, // P-256 curve
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, // 🔐 CRITICAL: Store in Secure Enclave
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.masterKeyTag.data(using: .utf8)!,
                kSecAttrAccessControl as String: access,
                kSecAttrLabel as String: Self.keyLabel
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SecureEnclaveError.keyGenerationFailed(
                (error!.takeRetainedValue() as Error) as? OSStatus ?? errSecInternalError
            )
        }

        return privateKey
    }

    /// Retrieve existing master key from Keychain
    private func retrieveMasterKey(context: LAContext? = nil) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.masterKeyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        // If LAContext is provided, use it for authentication
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw SecureEnclaveError.keyNotFound
            } else if status == errSecAuthFailed || status == errSecUserCanceled {
                throw SecureEnclaveError.biometricAuthenticationFailed
            } else {
                throw SecureEnclaveError.keyGenerationFailed(status)
            }
        }

        // Safe unwrapping - check type before casting
        guard let item = item else {
            throw SecureEnclaveError.keyNotFound
        }

        guard CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw SecureEnclaveError.invalidKeyData
        }

        let privateKey = (item as! SecKey)
        return privateKey
    }
}

// MARK: - Utility Extensions

extension SecureEnclaveManager {

    /// Get public key representation (for debugging/export)
    func getPublicKeyData() throws -> Data {
        let privateKey = try getMasterKey()

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.keyNotFound
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw SecureEnclaveError.encryptionFailed(error!.takeRetainedValue() as Error)
        }

        return publicKeyData
    }

    /// Verify key exists without requiring biometric auth
    func masterKeyExists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.masterKeyTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}

// MARK: - Logging & Auditing

extension SecureEnclaveManager {

    /// Log crypto operations for security auditing
    private func logCryptoOperation(_ operation: String, success: Bool) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let logEntry = "[\(timestamp)] Secure Enclave: \(operation) - \(success ? "SUCCESS" : "FAILURE")"

        // In production, write to secure audit log
        #if DEBUG
        print(logEntry)
        #endif

        // TODO: Implement secure audit logging to encrypted file
    }
}
