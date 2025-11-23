import Foundation
import CryptoKit
import LocalAuthentication

/// Complete vault management system with versioning, key rotation, and integrity
/// Coordinates SecureEnclave + Keychain + Encryption Engine
class VaultManager {

    // MARK: - Error Types

    enum VaultError: LocalizedError {
        case vaultNotInitialized
        case vaultAlreadyExists
        case keyDerivationFailed
        case encryptionFailed(Error)
        case decryptionFailed(Error)
        case versionMismatch
        case keyRotationFailed(Error)
        case integrityViolation
        case credentialNotFound
        case authenticationRequired

        var errorDescription: String? {
            switch self {
            case .vaultNotInitialized:
                return "Vault has not been initialized"
            case .vaultAlreadyExists:
                return "Vault already exists"
            case .keyDerivationFailed:
                return "Failed to derive encryption key"
            case .encryptionFailed(let error):
                return "Encryption failed: \(error.localizedDescription)"
            case .decryptionFailed(let error):
                return "Decryption failed: \(error.localizedDescription)"
            case .versionMismatch:
                return "Vault version mismatch"
            case .keyRotationFailed(let error):
                return "Key rotation failed: \(error.localizedDescription)"
            case .integrityViolation:
                return "Vault integrity check failed"
            case .credentialNotFound:
                return "Credential not found"
            case .authenticationRequired:
                return "Biometric authentication required"
            }
        }
    }

    // MARK: - Singleton

    static let shared = VaultManager()
    private init() {}

    // MARK: - Dependencies

    private let secureEnclave = SecureEnclaveManager.shared
    private let keychain = KeychainManager.shared
    private let biometric = BiometricAuthManager.shared

    // MARK: - In-Memory Session Cache

    private var sessionCDK: SymmetricKey?
    private var sessionExpiry: Date?
    private let sessionDuration: TimeInterval = 300 // 5 minutes

    private let queue = DispatchQueue(label: "com.securemvp.vault", qos: .userInitiated)

    // MARK: - Vault Initialization

    /// Initialize a new vault (first-time setup)
    /// - Throws: VaultError if initialization fails
    func initializeVault() async throws {
        print("🚀 ENTRY: initializeVault() called")
        print("📍 Thread: \(Thread.current)")
        print("📍 Is main thread: \(Thread.isMainThread)")

        // Check if vault already exists
        print("🔍 Checking if vault metadata exists in Keychain...")
        let vaultExists = keychain.exists(type: .vaultMetadata)
        print("📊 Vault exists check result: \(vaultExists)")

        if vaultExists {
            print("❌ Vault already exists - aborting initialization")
            throw VaultError.vaultAlreadyExists
        }
        print("✅ No existing vault - proceeding with initialization")

        print("🔐 Starting vault initialization...")

        // Ensure Secure Enclave is available
        guard secureEnclave.isSecureEnclaveAvailable() else {
            print("❌ Secure Enclave not available")
            throw VaultError.keyDerivationFailed
        }
        print("✅ Secure Enclave available")

        // Authenticate user before vault creation
        print("🔐 Requesting biometric authentication...")
        _ = try await biometric.authenticate(
            reason: "Create secure vault for your passwords",
            policy: .biometricOrPasscode
        )
        print("✅ Biometric authentication successful")

        // Generate Secure Enclave master key
        print("🔑 Generating Secure Enclave master key...")
        let _ = try secureEnclave.getMasterKey()
        print("✅ Master key generated")

        // Generate first KEK version
        print("🔑 Generating KEK v1...")
        let kekV1 = VaultEncryptionEngine.generateRandomKey()
        print("✅ KEK v1 generated")

        // Encrypt KEK with Secure Enclave
        print("🔐 Encrypting KEK with Secure Enclave...")
        let kekData = kekV1.withUnsafeBytes { Data($0) }
        let encryptedKEK = try secureEnclave.encrypt(kekData)
        print("✅ KEK encrypted")

        // Save encrypted KEK to Keychain
        print("💾 Saving KEK to Keychain...")
        let vaultKEK = VaultKEK(
            version: 1,
            encryptedKey: encryptedKEK,
            createdAt: Date()
        )
        try keychain.saveVaultKEK(vaultKEK)
        print("✅ KEK saved to Keychain")

        // Generate version-specific salt for CDK derivation
        print("🧂 Generating salt for CDK derivation...")
        let salt = try VaultEncryptionEngine.generateSalt()
        try keychain.save(salt, type: .encryptedSalt, account: "v1")
        print("✅ Salt saved")

        // Initialize vault metadata
        print("📋 Saving vault metadata...")
        let metadata = VaultMetadata(
            currentVersion: 1,
            totalCredentials: 0,
            rotationIntervalDays: 90
        )
        try keychain.saveVaultMetadata(metadata)
        print("✅ Metadata saved")

        print("✅ Vault initialized successfully with version 1")
    }

    /// Enable PIN authentication for the vault
    /// Creates a PIN-encrypted copy of the current KEK
    /// - Parameter pin: User's PIN (4-12 digits)
    /// - Throws: VaultError or PINError if setup fails
    func enablePINAuthentication(pin: String) async throws {
        print("🔐 Enabling PIN authentication...")

        // Vault must be initialized
        guard isVaultInitialized() else {
            throw VaultError.vaultNotInitialized
        }

        // Set up PIN in PINManager
        let pinManager = PINManager.shared
        try pinManager.setupPIN(pin)

        // Derive PIN encryption key
        let pinKey = try pinManager.derivePINKey(from: pin)

        // Get current KEK (need to unlock vault first if locked)
        let metadata = try keychain.retrieveVaultMetadata()

        // If vault is unlocked, we can get KEK from session
        // Otherwise, need biometric authentication
        let kek: SymmetricKey
        if let sessionKEK = try? getSessionKEK(version: metadata.currentVersion) {
            kek = sessionKEK
        } else {
            // Unlock with biometric to get KEK
            let context = try await biometric.authenticate(
                reason: "Enable PIN authentication",
                policy: .biometricOrPasscode
            )

            let vaultKEK = try keychain.retrieveVaultKEK(version: metadata.currentVersion)
            let kekData = try secureEnclave.decrypt(vaultKEK.encryptedKey, context: context)
            kek = try VaultEncryptionEngine.createKey(from: kekData)
        }

        // Encrypt KEK with PIN-derived key
        let kekData = kek.withUnsafeBytes { Data($0) }
        let pinEncryptedKEK = try VaultEncryptionEngine.encrypt(
            kekData,
            using: pinKey,
            associatedData: "pin-kek-v\(metadata.currentVersion)".data(using: .utf8)!,
            vaultVersion: metadata.currentVersion
        )

        // Save PIN-encrypted KEK to Keychain
        let encodedPayload = try JSONEncoder().encode(pinEncryptedKEK)
        try keychain.save(
            encodedPayload,
            type: .vaultKEK,
            account: "pin-encrypted-v\(metadata.currentVersion)",
            accessLevel: .standard
        )

        print("✅ PIN authentication enabled successfully")
    }

    /// Disable PIN authentication
    /// - Throws: KeychainError if deletion fails
    func disablePINAuthentication() throws {
        print("🔐 Disabling PIN authentication...")

        let pinManager = PINManager.shared
        try pinManager.removePIN()

        // Remove PIN-encrypted KEK
        let metadata = try keychain.retrieveVaultMetadata()
        try? keychain.delete(type: .vaultKEK, account: "pin-encrypted-v\(metadata.currentVersion)")

        print("✅ PIN authentication disabled")
    }

    /// Check if vault is initialized
    func isVaultInitialized() -> Bool {
        return keychain.exists(type: .vaultMetadata)
    }

    // MARK: - Session Management

    /// Unlock vault (authenticate and load CDK into memory)
    /// - Returns: true if unlock successful
    @discardableResult
    func unlockVault() async throws -> Bool {
        // 🔥 FIX: Check if vault is initialized first
        guard isVaultInitialized() else {
            print("❌ Vault not initialized - cannot unlock")
            throw VaultError.vaultNotInitialized
        }

        // Check if already unlocked
        if let expiry = sessionExpiry, Date() < expiry, sessionCDK != nil {
            print("✅ Vault already unlocked")
            return true // Already unlocked
        }

        print("🔐 Starting unlock process...")

        // Authenticate user
        let context = try await biometric.authenticate(
            reason: "Unlock your password vault",
            policy: .biometricOrPasscode
        )

        print("✅ Biometric authentication successful")

        // Load current KEK
        let metadata = try keychain.retrieveVaultMetadata()
        let vaultKEK = try keychain.retrieveVaultKEK(version: metadata.currentVersion)

        // Decrypt KEK using Secure Enclave
        let kekData = try secureEnclave.decrypt(vaultKEK.encryptedKey, context: context)
        let kek = try VaultEncryptionEngine.createKey(from: kekData)

        // Derive CDK from KEK
        let salt = try keychain.retrieve(type: .encryptedSalt, account: "v\(metadata.currentVersion)")
        let cdk = VaultEncryptionEngine.deriveKey(
            from: kek,
            salt: salt,
            info: "vault-cdk-v\(metadata.currentVersion)"
        )

        // Store CDK in memory
        queue.sync {
            self.sessionCDK = cdk
            self.sessionExpiry = Date().addingTimeInterval(sessionDuration)
        }

        print("🔓 Vault unlocked (session expires in \(sessionDuration)s)")
        return true
    }

    /// Unlock vault with PIN authentication
    /// - Parameter pin: User's PIN
    /// - Returns: true if unlock successful
    /// - Throws: VaultError or PINError if unlock fails
    @discardableResult
    func unlockVaultWithPIN(_ pin: String) async throws -> Bool {
        // 🔥 CHECK: Vault must be initialized
        guard isVaultInitialized() else {
            print("❌ Vault not initialized - cannot unlock")
            throw VaultError.vaultNotInitialized
        }

        // Check if already unlocked
        if let expiry = sessionExpiry, Date() < expiry, sessionCDK != nil {
            print("✅ Vault already unlocked")
            return true
        }

        print("🔐 Starting PIN unlock process...")

        // Verify PIN and derive encryption key
        let pinManager = PINManager.shared
        let pinKey = try pinManager.derivePINKey(from: pin)

        print("✅ PIN verified successfully")

        // Load current KEK
        let metadata = try keychain.retrieveVaultMetadata()
        let vaultKEK = try keychain.retrieveVaultKEK(version: metadata.currentVersion)

        // Decrypt KEK using PIN-derived key
        // Note: We need to re-encrypt the KEK with PIN-derived key during PIN setup
        // For now, this assumes KEK is encrypted with Secure Enclave only
        // TODO: Support dual authentication (PIN OR biometric)

        // For PIN-only unlock, we need a PIN-encrypted copy of the KEK
        // Let's retrieve it from a separate Keychain item
        let pinEncryptedKEKData = try keychain.retrieve(
            type: .vaultKEK,
            account: "pin-encrypted-v\(metadata.currentVersion)"
        )

        // Decrypt the PIN-encrypted KEK
        let encryptedPayload = try JSONDecoder().decode(
            VaultEncryptionEngine.EncryptedPayload.self,
            from: pinEncryptedKEKData
        )

        let kekData = try VaultEncryptionEngine.decrypt(encryptedPayload, using: pinKey)
        let kek = try VaultEncryptionEngine.createKey(from: kekData)

        // Derive CDK from KEK
        let salt = try keychain.retrieve(type: .encryptedSalt, account: "v\(metadata.currentVersion)")
        let cdk = VaultEncryptionEngine.deriveKey(
            from: kek,
            salt: salt,
            info: "vault-cdk-v\(metadata.currentVersion)"
        )

        // Store CDK in memory
        queue.sync {
            self.sessionCDK = cdk
            self.sessionExpiry = Date().addingTimeInterval(sessionDuration)
        }

        print("🔓 Vault unlocked with PIN (session expires in \(sessionDuration)s)")
        return true
    }

    /// Lock vault (clear session keys)
    func lockVault() {
        queue.sync {
            sessionCDK = nil
            sessionExpiry = nil
        }
        print("🔒 Vault locked")
    }

    /// Check if vault is currently unlocked
    var isUnlocked: Bool {
        queue.sync {
            if let expiry = sessionExpiry, Date() < expiry, sessionCDK != nil {
                return true
            }
            return false
        }
    }

    /// Extend session expiry (call on user activity)
    func extendSession() {
        queue.sync {
            if sessionCDK != nil {
                sessionExpiry = Date().addingTimeInterval(sessionDuration)
            }
        }
    }

    // MARK: - Credential Storage

    /// Save encrypted credential to vault
    /// - Parameter credential: Credential to encrypt and store
    /// - Throws: VaultError if encryption or storage fails
    func saveCredential(_ credential: Credential) async throws {
        // Ensure vault is unlocked
        guard let cdk = try await getSessionCDK() else {
            throw VaultError.authenticationRequired
        }

        // Build AAD from credential metadata
        let aad = VaultEncryptionEngine.buildAAD(
            username: credential.username,
            domain: credential.domain,
            credentialID: credential.id,
            vaultVersion: try keychain.retrieveVaultMetadata().currentVersion
        )

        // Encrypt password
        let plaintextData = Data(credential.password.utf8)
        let encryptedPayload = try VaultEncryptionEngine.encrypt(
            plaintextData,
            using: cdk,
            associatedData: aad,
            vaultVersion: try keychain.retrieveVaultMetadata().currentVersion
        )

        // Store encrypted credential (in real app, use database or file storage)
        // For MVP, we'll use Keychain as temporary storage
        let credentialData = try JSONEncoder().encode(encryptedPayload)
        try keychain.save(
            credentialData,
            type: .vaultMetadata, // Reusing type for demo
            account: "cred-\(credential.id.uuidString)"
        )

        // Update metadata with credential ID index
        var metadata = try keychain.retrieveVaultMetadata()

        // 🔥 NEW: Add credential ID to index (prevent duplicates)
        if !metadata.credentialIDs.contains(credential.id) {
            metadata.credentialIDs.append(credential.id)
            metadata.totalCredentials += 1
        }

        metadata.lastModified = Date()
        try keychain.saveVaultMetadata(metadata)

        print("✅ Credential saved: \(credential.domain) (ID: \(credential.id))")
    }

    /// Retrieve and decrypt credential from vault
    /// - Parameter credentialID: UUID of credential to retrieve
    /// - Returns: Decrypted credential
    /// - Throws: VaultError if decryption fails
    func retrieveCredential(id: UUID) async throws -> String {
        // Ensure vault is unlocked
        guard let cdk = try await getSessionCDK() else {
            throw VaultError.authenticationRequired
        }

        // Load encrypted payload
        let credentialData = try keychain.retrieve(
            type: .vaultMetadata,
            account: "cred-\(id.uuidString)"
        )

        let encryptedPayload = try JSONDecoder().decode(
            VaultEncryptionEngine.EncryptedPayload.self,
            from: credentialData
        )

        // Decrypt password
        let plaintextData = try VaultEncryptionEngine.decrypt(encryptedPayload, using: cdk)

        guard let password = String(data: plaintextData, encoding: .utf8) else {
            throw VaultError.decryptionFailed(
                NSError(domain: "VaultManager", code: -1,
                       userInfo: [NSLocalizedDescriptionKey: "Invalid password data"])
            )
        }

        return password
    }

    /// List all credentials in the vault
    /// 🔥 NEW: Retrieves and decrypts all stored credentials
    /// - Returns: Array of decrypted credentials
    /// - Throws: VaultError if vault is locked or decryption fails
    func listAllCredentials() async throws -> [Credential] {
        // Ensure vault is unlocked
        guard let cdk = try await getSessionCDK() else {
            throw VaultError.authenticationRequired
        }

        // Get credential IDs from metadata
        let metadata = try keychain.retrieveVaultMetadata()
        var credentials: [Credential] = []

        print("📋 Loading \(metadata.credentialIDs.count) credentials...")

        for credentialID in metadata.credentialIDs {
            do {
                // Load encrypted payload
                let credentialData = try keychain.retrieve(
                    type: .vaultMetadata,
                    account: "cred-\(credentialID.uuidString)"
                )

                let encryptedPayload = try JSONDecoder().decode(
                    VaultEncryptionEngine.EncryptedPayload.self,
                    from: credentialData
                )

                // Decrypt password
                let plaintextData = try VaultEncryptionEngine.decrypt(encryptedPayload, using: cdk)

                guard let password = String(data: plaintextData, encoding: .utf8) else {
                    print("⚠️ Failed to decode password for credential \(credentialID)")
                    continue
                }

                // Extract metadata from AAD
                guard let (username, domain, _, _) = VaultEncryptionEngine.parseAAD(encryptedPayload.aad) else {
                    print("⚠️ Failed to parse AAD for credential \(credentialID)")
                    continue
                }

                // Build credential object
                let credential = Credential(
                    id: credentialID,
                    domain: domain,
                    username: username,
                    password: password,
                    notes: nil  // TODO: Add notes to encrypted payload
                )

                credentials.append(credential)
                print("  ✅ Loaded: \(domain) / \(username)")

            } catch {
                print("⚠️ Failed to load credential \(credentialID): \(error.localizedDescription)")
                // Continue loading other credentials even if one fails
                continue
            }
        }

        print("✅ Loaded \(credentials.count) of \(metadata.credentialIDs.count) credentials")
        return credentials
    }

    /// Delete a credential from the vault
    /// 🔥 NEW: Removes credential and updates index
    /// - Parameter id: UUID of credential to delete
    /// - Throws: VaultError if deletion fails
    func deleteCredential(id: UUID) async throws {
        // Delete from Keychain
        try keychain.delete(type: .vaultMetadata, account: "cred-\(id.uuidString)")

        // Update metadata index
        var metadata = try keychain.retrieveVaultMetadata()
        metadata.credentialIDs.removeAll { $0 == id }
        metadata.totalCredentials = metadata.credentialIDs.count
        metadata.lastModified = Date()
        try keychain.saveVaultMetadata(metadata)

        print("🗑️ Credential deleted: \(id)")
    }

    /// Update an existing credential
    /// 🔥 NEW: Updates credential password, username, or notes
    /// - Parameters:
    ///   - id: UUID of credential to update
    ///   - newPassword: New password (nil to keep existing)
    ///   - newUsername: New username (nil to keep existing)
    ///   - newNotes: New notes (nil to keep existing)
    /// - Throws: VaultError if update fails
    func updateCredential(
        id: UUID,
        newPassword: String? = nil,
        newUsername: String? = nil,
        newNotes: String? = nil
    ) async throws {
        // Ensure vault is unlocked
        guard let cdk = try await getSessionCDK() else {
            throw VaultError.authenticationRequired
        }

        // Load existing encrypted payload to get current values
        let credentialData = try keychain.retrieve(
            type: .vaultMetadata,
            account: "cred-\(id.uuidString)"
        )

        let encryptedPayload = try JSONDecoder().decode(
            VaultEncryptionEngine.EncryptedPayload.self,
            from: credentialData
        )

        // Decrypt current password
        let currentPasswordData = try VaultEncryptionEngine.decrypt(encryptedPayload, using: cdk)
        guard let currentPassword = String(data: currentPasswordData, encoding: .utf8) else {
            throw VaultError.decryptionFailed(
                NSError(domain: "VaultManager", code: -1,
                       userInfo: [NSLocalizedDescriptionKey: "Invalid password data"])
            )
        }

        // Extract current metadata from AAD
        guard let (currentUsername, currentDomain, _, _) = VaultEncryptionEngine.parseAAD(encryptedPayload.aad) else {
            throw VaultError.decryptionFailed(
                NSError(domain: "VaultManager", code: -1,
                       userInfo: [NSLocalizedDescriptionKey: "Failed to parse AAD"])
            )
        }

        // Use new values if provided, otherwise keep current
        let finalPassword = newPassword ?? currentPassword
        let finalUsername = newUsername ?? currentUsername
        let finalNotes = newNotes  // Notes are optional, so we use the new value directly

        // Build new AAD with updated username
        let metadata = try keychain.retrieveVaultMetadata()
        let aad = VaultEncryptionEngine.buildAAD(
            username: finalUsername,
            domain: currentDomain,  // Domain cannot be changed
            credentialID: id,
            vaultVersion: metadata.currentVersion
        )

        // Encrypt updated password
        let plaintextData = Data(finalPassword.utf8)
        let newEncryptedPayload = try VaultEncryptionEngine.encrypt(
            plaintextData,
            using: cdk,
            associatedData: aad,
            vaultVersion: metadata.currentVersion
        )

        // Save updated credential
        let newCredentialData = try JSONEncoder().encode(newEncryptedPayload)
        try keychain.save(
            newCredentialData,
            type: .vaultMetadata,
            account: "cred-\(id.uuidString)"
        )

        // Update metadata timestamp
        var updatedMetadata = metadata
        updatedMetadata.lastModified = Date()
        try keychain.saveVaultMetadata(updatedMetadata)

        print("✏️ Credential updated: \(currentDomain)")
    }

    // MARK: - Key Rotation

    /// Rotate vault KEK (create new version, re-encrypt all credentials)
    /// - Throws: VaultError if rotation fails
    func rotateVaultKey() async throws {
        print("🔄 Starting key rotation...")

        // Authenticate user
        let context = try await biometric.authenticate(
            reason: "Rotate encryption keys for enhanced security",
            policy: .biometricOrPasscode
        )

        // Get current metadata
        var metadata = try keychain.retrieveVaultMetadata()
        let oldVersion = metadata.currentVersion
        let newVersion = oldVersion + 1

        // Generate new KEK
        let newKEK = VaultEncryptionEngine.generateRandomKey()
        let newKEKData = newKEK.withUnsafeBytes { Data($0) }
        let encryptedNewKEK = try secureEnclave.encrypt(newKEKData)

        // Save new KEK version
        let vaultKEK = VaultKEK(
            version: newVersion,
            encryptedKey: encryptedNewKEK,
            createdAt: Date()
        )
        try keychain.saveVaultKEK(vaultKEK)

        // Generate new salt
        let newSalt = try VaultEncryptionEngine.generateSalt()
        try keychain.save(newSalt, type: .encryptedSalt, account: "v\(newVersion)")

        // Derive new CDK
        let newCDK = VaultEncryptionEngine.deriveKey(
            from: newKEK,
            salt: newSalt,
            info: "vault-cdk-v\(newVersion)"
        )

        // 🔥 FIXED: Re-encrypt all credentials with new CDK
        print("🔐 Re-encrypting \(metadata.credentialIDs.count) credentials...")

        // Get old CDK for decryption
        let oldKEK = try getSessionKEK(version: oldVersion)
        let oldSalt = try keychain.retrieve(type: .encryptedSalt, account: "v\(oldVersion)")
        let oldCDK = VaultEncryptionEngine.deriveKey(
            from: oldKEK,
            salt: oldSalt,
            info: "vault-cdk-v\(oldVersion)"
        )

        var successCount = 0
        var failureCount = 0

        // Re-encrypt each credential
        for credentialID in metadata.credentialIDs {
            do {
                // Load encrypted payload (old CDK)
                let credentialData = try keychain.retrieve(
                    type: .vaultMetadata,
                    account: "cred-\(credentialID.uuidString)"
                )

                let oldPayload = try JSONDecoder().decode(
                    VaultEncryptionEngine.EncryptedPayload.self,
                    from: credentialData
                )

                // Decrypt with old CDK
                let plaintextData = try VaultEncryptionEngine.decrypt(oldPayload, using: oldCDK)

                // Extract AAD and update version
                guard let (username, domain, uuid, _) = VaultEncryptionEngine.parseAAD(oldPayload.aad) else {
                    print("⚠️ Failed to parse AAD for credential \(credentialID)")
                    failureCount += 1
                    continue
                }

                // Build new AAD with new version
                let newAAD = VaultEncryptionEngine.buildAAD(
                    username: username,
                    domain: domain,
                    credentialID: uuid,
                    vaultVersion: newVersion
                )

                // Re-encrypt with new CDK
                let newPayload = try VaultEncryptionEngine.encrypt(
                    plaintextData,
                    using: newCDK,
                    associatedData: newAAD,
                    vaultVersion: newVersion
                )

                // Save re-encrypted credential
                let newCredentialData = try JSONEncoder().encode(newPayload)
                try keychain.save(
                    newCredentialData,
                    type: .vaultMetadata,
                    account: "cred-\(credentialID.uuidString)"
                )

                successCount += 1
                print("  ✅ Re-encrypted: \(domain)")

            } catch {
                print("  ❌ Failed to re-encrypt credential \(credentialID): \(error)")
                failureCount += 1
            }
        }

        print("🔐 Re-encryption complete: \(successCount) success, \(failureCount) failed")

        if failureCount > 0 {
            throw VaultError.keyRotationFailed(
                NSError(domain: "VaultManager", code: -1,
                       userInfo: [NSLocalizedDescriptionKey: "Failed to re-encrypt \(failureCount) credentials"])
            )
        }

        // Update metadata
        metadata.currentVersion = newVersion
        metadata.lastKeyRotation = Date()
        metadata.lastModified = Date()
        try keychain.saveVaultMetadata(metadata)

        // Update session with new CDK
        queue.sync {
            self.sessionCDK = newCDK
            self.sessionExpiry = Date().addingTimeInterval(sessionDuration)
        }

        print("✅ Key rotation complete: v\(oldVersion) -> v\(newVersion)")
    }

    /// Check if key rotation is due
    func isKeyRotationDue() throws -> Bool {
        let metadata = try keychain.retrieveVaultMetadata()
        return metadata.isKeyRotationDue
    }

    // MARK: - Private Helpers

    /// Get CDK from session or authenticate to load it
    private func getSessionCDK() async throws -> SymmetricKey? {
        // Check session validity
        if let expiry = sessionExpiry, Date() < expiry, let cdk = sessionCDK {
            return cdk
        }

        // Session expired, re-authenticate
        try await unlockVault()
        return sessionCDK
    }

    /// Get decrypted KEK for a specific version (used in key rotation)
    /// - Parameter version: Vault version number
    /// - Returns: Decrypted KEK as SymmetricKey
    /// - Throws: VaultError if retrieval or decryption fails
    private func getSessionKEK(version: Int) throws -> SymmetricKey {
        // Retrieve encrypted KEK for specified version
        let vaultKEK = try keychain.retrieveVaultKEK(version: version)

        // Decrypt KEK using Secure Enclave
        let kekData = try secureEnclave.decrypt(vaultKEK.encryptedKey)

        // Convert to SymmetricKey
        return try VaultEncryptionEngine.createKey(from: kekData)
    }

    // MARK: - Vault Statistics

    func getVaultStats() throws -> VaultStats {
        let metadata = try keychain.retrieveVaultMetadata()

        return VaultStats(
            totalCredentials: metadata.totalCredentials,
            currentVersion: metadata.currentVersion,
            lastModified: metadata.lastModified,
            lastKeyRotation: metadata.lastKeyRotation,
            isRotationDue: metadata.isKeyRotationDue,
            isUnlocked: isUnlocked
        )
    }

    // MARK: - Vault Reset (DANGEROUS!)

    /// Delete entire vault and all credentials
    /// ⚠️ WARNING: This is irreversible!
    func resetVault() async throws {
        // Require authentication
        _ = try await biometric.authenticate(
            reason: "⚠️ Delete all vault data",
            policy: .biometricOrPasscode
        )

        // Delete all Keychain data
        try keychain.deleteAllVaultData()

        // Delete Secure Enclave master key
        try secureEnclave.deleteMasterKey()

        // Clear session
        lockVault()

        print("⚠️ Vault completely reset")
    }
}

// MARK: - Data Models

/// Credential entity
struct Credential: Identifiable, Codable {
    let id: UUID
    let domain: String
    let username: String
    let password: String
    let createdAt: Date
    let modifiedAt: Date
    let notes: String?

    init(
        id: UUID = UUID(),
        domain: String,
        username: String,
        password: String,
        notes: String? = nil
    ) {
        self.id = id
        self.domain = domain
        self.username = username
        self.password = password
        self.createdAt = Date()
        self.modifiedAt = Date()
        self.notes = notes
    }
}

/// Vault statistics
struct VaultStats {
    let totalCredentials: Int
    let currentVersion: Int
    let lastModified: Date
    let lastKeyRotation: Date?
    let isRotationDue: Bool
    let isUnlocked: Bool

    var statusDescription: String {
        let status = isUnlocked ? "🔓 Unlocked" : "🔒 Locked"
        return """
        \(status)
        Credentials: \(totalCredentials)
        Vault Version: \(currentVersion)
        Rotation Due: \(isRotationDue ? "⚠️ Yes" : "✅ No")
        """
    }
}
