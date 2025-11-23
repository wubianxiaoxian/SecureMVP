import Foundation
import Security
import CryptoKit

/// Enterprise-grade Keychain manager for secure storage
/// - Stores encrypted KEKs, vault metadata, and sensitive configuration
/// - Implements access control with biometric protection
/// - Supports versioning and key rotation
/// - Thread-safe operations
class KeychainManager {

    // MARK: - Error Types

    enum KeychainError: LocalizedError {
        case itemNotFound
        case duplicateItem
        case saveFailed(OSStatus)
        case updateFailed(OSStatus)
        case deleteFailed(OSStatus)
        case queryFailed(OSStatus)
        case invalidData
        case encodingFailed
        case decodingFailed
        case accessDenied

        var errorDescription: String? {
            switch self {
            case .itemNotFound:
                return "Keychain item not found"
            case .duplicateItem:
                return "Keychain item already exists"
            case .saveFailed(let status):
                return "Failed to save to Keychain: \(status)"
            case .updateFailed(let status):
                return "Failed to update Keychain item: \(status)"
            case .deleteFailed(let status):
                return "Failed to delete from Keychain: \(status)"
            case .queryFailed(let status):
                return "Keychain query failed: \(status)"
            case .invalidData:
                return "Invalid data format"
            case .encodingFailed:
                return "Failed to encode data"
            case .decodingFailed:
                return "Failed to decode data"
            case .accessDenied:
                return "Access to Keychain denied - biometric authentication may be required"
            }
        }
    }

    // MARK: - Item Types

    enum ItemType: String {
        case vaultKEK = "com.securemvp.vault.kek"
        case vaultMetadata = "com.securemvp.vault.metadata"
        case vaultVersion = "com.securemvp.vault.version"
        case encryptedSalt = "com.securemvp.vault.salt"
        case sentinelModel = "com.securemvp.sentinel.model"
        case userPreferences = "com.securemvp.user.prefs"

        var service: String {
            return "SecureMVP"
        }
    }

    // MARK: - Access Control Levels

    enum AccessLevel {
        case standard                    // When unlocked
        case biometricProtected         // Biometric required
        case biometricOrPasscode        // Biometric or device passcode

        var accessControl: SecAccessControl? {
            switch self {
            case .standard:
                return nil // Use default accessibility

            case .biometricProtected:
                return SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    .biometryAny,
                    nil
                )

            case .biometricOrPasscode:
                return SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.biometryAny, .or, .devicePasscode],
                    nil
                )
            }
        }

        var accessibility: CFString {
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }

    // MARK: - Singleton

    static let shared = KeychainManager()
    private init() {}

    // MARK: - Configuration

    /// Keychain access group for sharing between app and extension
    /// Format: $(AppIdentifierPrefix)com.securemvp.app
    /// TEMPORARY FIX: Disabled for simulator compatibility (error -34018)
    /// TODO: Enable when deploying to real device with proper Team ID
    private let accessGroup: String = ""  // Empty = no access group restriction

    // MARK: - Thread Safety

    private let queue = DispatchQueue(label: "com.securemvp.keychain", qos: .userInitiated)

    // MARK: - Public Interface - Generic Storage

    /// Save data to Keychain
    /// - Parameters:
    ///   - data: Data to store
    ///   - type: Item type
    ///   - account: Account identifier (optional, default: "default")
    ///   - accessLevel: Security level
    /// - Throws: KeychainError if save fails
    func save(
        _ data: Data,
        type: ItemType,
        account: String = "default",
        accessLevel: AccessLevel = .standard
    ) throws {
        print("💾 KeychainManager.save() - type: \(type.rawValue), account: \(account)")
        print("💾 Service: \(type.service)")
        print("💾 Access group: \(accessGroup)")
        print("💾 Access level: \(accessLevel)")
        print("💾 Data size: \(data.count) bytes")

        try queue.sync {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: type.service,
                kSecAttrAccount as String: "\(type.rawValue).\(account)",
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessLevel.accessibility
            ]

            // Only add access group if not empty (simulator compatibility)
            if !accessGroup.isEmpty {
                query[kSecAttrAccessGroup as String] = accessGroup
            }

            // Add access control if specified
            if let accessControl = accessLevel.accessControl {
                print("💾 Adding access control (biometric)")
                query[kSecAttrAccessControl as String] = accessControl
                query.removeValue(forKey: kSecAttrAccessible as String) // Can't use both
            }

            // Try to save
            print("💾 Attempting SecItemAdd...")
            var status = SecItemAdd(query as CFDictionary, nil)
            print("💾 SecItemAdd status: \(status)")

            // If item exists, update it
            if status == errSecDuplicateItem {
                print("💾 Item exists, updating...")
                var updateQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: type.service,
                    kSecAttrAccount as String: "\(type.rawValue).\(account)"
                ]

                // Only add access group if not empty (simulator compatibility)
                if !accessGroup.isEmpty {
                    updateQuery[kSecAttrAccessGroup as String] = accessGroup
                }

                let updateAttributes: [String: Any] = [
                    kSecValueData as String: data
                ]

                status = SecItemUpdate(updateQuery as CFDictionary, updateAttributes as CFDictionary)
                print("💾 SecItemUpdate status: \(status)")

                if status != errSecSuccess {
                    print("❌ Update failed with status: \(status)")
                    throw KeychainError.updateFailed(status)
                }
                print("✅ Item updated successfully")
            } else if status != errSecSuccess {
                print("❌ Save failed with status: \(status)")
                throw KeychainError.saveFailed(status)
            } else {
                print("✅ Item saved successfully")
            }
        }
    }

    /// Retrieve data from Keychain
    /// - Parameters:
    ///   - type: Item type
    ///   - account: Account identifier
    /// - Returns: Stored data
    /// - Throws: KeychainError if retrieval fails
    func retrieve(
        type: ItemType,
        account: String = "default"
    ) throws -> Data {
        try queue.sync {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: type.service,
                kSecAttrAccount as String: "\(type.rawValue).\(account)",
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]

            // Only add access group if not empty (simulator compatibility)
            if !accessGroup.isEmpty {
                query[kSecAttrAccessGroup as String] = accessGroup
            }

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            guard status != errSecItemNotFound else {
                throw KeychainError.itemNotFound
            }

            guard status == errSecSuccess else {
                if status == errSecAuthFailed || status == errSecUserCanceled {
                    throw KeychainError.accessDenied
                }
                throw KeychainError.queryFailed(status)
            }

            guard let data = item as? Data else {
                throw KeychainError.invalidData
            }

            return data
        }
    }

    /// Delete item from Keychain
    /// - Parameters:
    ///   - type: Item type
    ///   - account: Account identifier
    /// - Throws: KeychainError if deletion fails
    func delete(
        type: ItemType,
        account: String = "default"
    ) throws {
        try queue.sync {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: type.service,
                kSecAttrAccount as String: "\(type.rawValue).\(account)"
            ]

            // Only add access group if not empty (simulator compatibility)
            if !accessGroup.isEmpty {
                query[kSecAttrAccessGroup as String] = accessGroup
            }

            let status = SecItemDelete(query as CFDictionary)

            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError.deleteFailed(status)
            }
        }
    }

    /// Check if item exists
    /// - Parameters:
    ///   - type: Item type
    ///   - account: Account identifier
    /// - Returns: true if item exists
    func exists(
        type: ItemType,
        account: String = "default"
    ) -> Bool {
        print("🔍 KeychainManager.exists() - type: \(type.rawValue), account: \(account)")
        print("🔍 Service: \(type.service)")
        print("🔍 Access group: \(accessGroup.isEmpty ? "(none - simulator mode)" : accessGroup)")

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: type.service,
            kSecAttrAccount as String: "\(type.rawValue).\(account)",
            kSecReturnData as String: false
        ]

        // Only add access group if not empty (simulator compatibility)
        if !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        let exists = status == errSecSuccess

        print("🔍 Keychain query status: \(status) (\(status == errSecSuccess ? "SUCCESS" : status == errSecItemNotFound ? "NOT FOUND" : "ERROR"))")
        print("🔍 Item exists: \(exists)")

        return exists
    }

    // MARK: - Codable Storage

    /// Save Codable object to Keychain
    func save<T: Codable>(
        _ object: T,
        type: ItemType,
        account: String = "default",
        accessLevel: AccessLevel = .standard
    ) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        encoder.dateEncodingStrategy = .iso8601

        guard let data = try? encoder.encode(object) else {
            throw KeychainError.encodingFailed
        }

        try save(data, type: type, account: account, accessLevel: accessLevel)
    }

    /// Retrieve Codable object from Keychain
    func retrieve<T: Codable>(
        type: ItemType,
        account: String = "default",
        as objectType: T.Type
    ) throws -> T {
        let data = try retrieve(type: type, account: account)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        guard let object = try? decoder.decode(T.self, from: data) else {
            throw KeychainError.decodingFailed
        }

        return object
    }

    // MARK: - Specialized Methods for Vault

    /// Save Vault KEK (encrypted by Secure Enclave)
    func saveVaultKEK(_ kek: VaultKEK) throws {
        // TEMPORARY: Use .standard for simulator compatibility
        // TODO: Change to .biometricProtected for production on real device
        try save(kek, type: .vaultKEK, account: "v\(kek.version)", accessLevel: .standard)
    }

    /// Retrieve Vault KEK by version
    func retrieveVaultKEK(version: Int) throws -> VaultKEK {
        try retrieve(type: .vaultKEK, account: "v\(version)", as: VaultKEK.self)
    }

    /// Retrieve current (latest) Vault KEK
    func retrieveCurrentVaultKEK() throws -> VaultKEK {
        let metadata = try retrieveVaultMetadata()
        return try retrieveVaultKEK(version: metadata.currentVersion)
    }

    /// Save vault metadata
    func saveVaultMetadata(_ metadata: VaultMetadata) throws {
        try save(metadata, type: .vaultMetadata, accessLevel: .standard)
    }

    /// Retrieve vault metadata
    func retrieveVaultMetadata() throws -> VaultMetadata {
        try retrieve(type: .vaultMetadata, as: VaultMetadata.self)
    }

    /// Delete all vault-related items (DANGEROUS!)
    func deleteAllVaultData() throws {
        // Get all KEK versions
        if let metadata = try? retrieveVaultMetadata() {
            for version in 1...metadata.currentVersion {
                try? delete(type: .vaultKEK, account: "v\(version)")
                try? delete(type: .encryptedSalt, account: "v\(version)")
            }
        }

        try? delete(type: .vaultMetadata)
        try? delete(type: .vaultVersion)
    }

    // MARK: - Debugging & Diagnostics

    func listAllItems() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ItemType.vaultKEK.service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrAccessGroup as String: accessGroup  // 🔥 NEW: App Groups sharing
        ]

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)

        guard status == errSecSuccess,
              let itemsArray = items as? [[String: Any]] else {
            return []
        }

        return itemsArray.compactMap { item in
            item[kSecAttrAccount as String] as? String
        }
    }
}

// MARK: - Data Models

/// Vault KEK (Key Encryption Key)
struct VaultKEK: Codable {
    let version: Int
    let encryptedKey: Data        // KEK encrypted by Secure Enclave
    let createdAt: Date
    let rotatedAt: Date?
    let algorithm: String          // "AES-256"
    let status: KEKStatus

    enum KEKStatus: String, Codable {
        case active
        case deprecated
        case archived
    }

    init(
        version: Int,
        encryptedKey: Data,
        createdAt: Date = Date(),
        algorithm: String = "AES-256"
    ) {
        self.version = version
        self.encryptedKey = encryptedKey
        self.createdAt = createdAt
        self.rotatedAt = nil
        self.algorithm = algorithm
        self.status = .active
    }
}

/// Vault Metadata
struct VaultMetadata: Codable {
    var currentVersion: Int
    var totalCredentials: Int
    var credentialIDs: [UUID]      // 🔥 NEW: Index of all stored credentials
    var createdAt: Date
    var lastModified: Date
    var lastKeyRotation: Date?
    var rotationIntervalDays: Int  // Auto-rotate KEK every N days

    // 🔥 CRITICAL FIX: Custom coding keys to support backward compatibility
    enum CodingKeys: String, CodingKey {
        case currentVersion
        case totalCredentials
        case credentialIDs
        case createdAt
        case lastModified
        case lastKeyRotation
        case rotationIntervalDays
    }

    init(
        currentVersion: Int = 1,
        totalCredentials: Int = 0,
        credentialIDs: [UUID] = [],  // 🔥 NEW: Default empty array
        rotationIntervalDays: Int = 90
    ) {
        self.currentVersion = currentVersion
        self.totalCredentials = totalCredentials
        self.credentialIDs = credentialIDs  // 🔥 NEW
        self.createdAt = Date()
        self.lastModified = Date()
        self.lastKeyRotation = nil
        self.rotationIntervalDays = rotationIntervalDays
    }

    // 🔥 CRITICAL FIX: Custom decoder for backward compatibility
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        currentVersion = try container.decode(Int.self, forKey: .currentVersion)
        totalCredentials = try container.decode(Int.self, forKey: .totalCredentials)

        // 🔥 FIX: credentialIDs is optional for backward compatibility
        credentialIDs = try container.decodeIfPresent([UUID].self, forKey: .credentialIDs) ?? []

        createdAt = try container.decode(Date.self, forKey: .createdAt)
        lastModified = try container.decode(Date.self, forKey: .lastModified)
        lastKeyRotation = try container.decodeIfPresent(Date.self, forKey: .lastKeyRotation)
        rotationIntervalDays = try container.decode(Int.self, forKey: .rotationIntervalDays)

        print("✅ VaultMetadata decoded - credentialIDs: \(credentialIDs.count) items")
    }

    /// Check if key rotation is due
    var isKeyRotationDue: Bool {
        guard let lastRotation = lastKeyRotation else {
            return true // Never rotated
        }

        let daysSinceRotation = Calendar.current.dateComponents(
            [.day],
            from: lastRotation,
            to: Date()
        ).day ?? 0

        return daysSinceRotation >= rotationIntervalDays
    }
}

// MARK: - Extensions

extension KeychainManager {

    /// Clear all SecureMVP items from Keychain (for testing/reset)
    func clearAll() throws {
        let types: [ItemType] = [.vaultKEK, .vaultMetadata, .vaultVersion, .encryptedSalt, .sentinelModel, .userPreferences]

        for type in types {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: type.service,
                kSecAttrAccessGroup as String: accessGroup  // 🔥 NEW: App Groups sharing
            ]

            SecItemDelete(query as CFDictionary) // Ignore errors
        }
    }
}
