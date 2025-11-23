import Foundation
import LocalAuthentication

/// Enterprise-grade biometric authentication manager
/// - Supports Face ID and Touch ID
/// - Fallback to device passcode
/// - Retry logic and lockout prevention
/// - Audit logging for security monitoring
class BiometricAuthManager {

    // MARK: - Error Types

    enum AuthError: LocalizedError {
        case biometricsNotAvailable
        case biometricsNotEnrolled
        case authenticationFailed(Error)
        case userCanceled
        case maxAttemptsExceeded
        case passcodeNotSet
        case contextNotAvailable

        var errorDescription: String? {
            switch self {
            case .biometricsNotAvailable:
                return "Biometric authentication is not available on this device"
            case .biometricsNotEnrolled:
                return "No biometric credentials are enrolled. Please set up Face ID or Touch ID."
            case .authenticationFailed(let error):
                return "Authentication failed: \(error.localizedDescription)"
            case .userCanceled:
                return "User canceled authentication"
            case .maxAttemptsExceeded:
                return "Too many failed attempts. Please try again later."
            case .passcodeNotSet:
                return "Device passcode is not set"
            case .contextNotAvailable:
                return "Authentication context is not available"
            }
        }
    }

    // MARK: - Biometric Type

    enum BiometricType {
        case none
        case touchID
        case faceID
        case opticID  // For Vision Pro

        var displayName: String {
            switch self {
            case .none: return "None"
            case .touchID: return "Touch ID"
            case .faceID: return "Face ID"
            case .opticID: return "Optic ID"
            }
        }

        var icon: String {
            switch self {
            case .none: return "lock.fill"
            case .touchID: return "touchid"
            case .faceID: return "faceid"
            case .opticID: return "opticid"
            }
        }
    }

    // MARK: - Authentication Policy

    enum AuthPolicy {
        case biometricOnly              // Face ID/Touch ID only
        case biometricOrPasscode        // Biometric or device passcode
        case deviceOwnerAuthentication  // Any available method

        var laPolicy: LAPolicy {
            switch self {
            case .biometricOnly:
                return .deviceOwnerAuthenticationWithBiometrics
            case .biometricOrPasscode, .deviceOwnerAuthentication:
                return .deviceOwnerAuthentication
            }
        }
    }

    // MARK: - Singleton

    static let shared = BiometricAuthManager()
    private init() {}

    // MARK: - Failed Attempt Tracking

    private var failedAttempts: Int = 0
    private let maxFailedAttempts = 5
    private var lockoutUntil: Date?

    // MARK: - Public Interface

    /// Get available biometric type on this device
    func getBiometricType() -> BiometricType {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }

        switch context.biometryType {
        case .none:
            return .none
        case .touchID:
            return .touchID
        case .faceID:
            return .faceID
        case .opticID:
            return .opticID
        @unknown default:
            return .none
        }
    }

    /// Check if biometric authentication is available
    func isBiometricAvailable() -> Bool {
        return getBiometricType() != .none
    }

    /// Check if device passcode is set
    func isPasscodeSet() -> Bool {
        let context = LAContext()
        var error: NSError?

        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    /// Authenticate user with biometrics or passcode
    /// - Parameters:
    ///   - reason: User-facing reason for authentication
    ///   - policy: Authentication policy (biometric only vs. biometric + passcode)
    ///   - fallbackTitle: Custom fallback button title (optional)
    /// - Returns: LAContext that can be used for Keychain operations
    /// - Throws: AuthError if authentication fails
    func authenticate(
        reason: String,
        policy: AuthPolicy = .biometricOnly,
        fallbackTitle: String? = nil
    ) async throws -> LAContext {

        // Check for lockout
        if let lockoutUntil = lockoutUntil, Date() < lockoutUntil {
            logAuthAttempt(success: false, reason: "Locked out")
            throw AuthError.maxAttemptsExceeded
        }

        // Create authentication context
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"

        if let fallbackTitle = fallbackTitle {
            context.localizedFallbackTitle = fallbackTitle
        }

        // Check if policy is available
        var error: NSError?
        guard context.canEvaluatePolicy(policy.laPolicy, error: &error) else {
            if let error = error {
                switch error.code {
                case LAError.biometryNotAvailable.rawValue:
                    throw AuthError.biometricsNotAvailable
                case LAError.biometryNotEnrolled.rawValue:
                    throw AuthError.biometricsNotEnrolled
                case LAError.passcodeNotSet.rawValue:
                    throw AuthError.passcodeNotSet
                default:
                    throw AuthError.authenticationFailed(error)
                }
            }
            throw AuthError.biometricsNotAvailable
        }

        // Perform authentication
        do {
            let success = try await context.evaluatePolicy(policy.laPolicy, localizedReason: reason)

            if success {
                failedAttempts = 0
                lockoutUntil = nil
                logAuthAttempt(success: true, reason: reason)
                return context // Return context for Keychain usage
            } else {
                throw AuthError.authenticationFailed(
                    NSError(domain: "BiometricAuth", code: -1,
                           userInfo: [NSLocalizedDescriptionKey: "Authentication returned false"])
                )
            }

        } catch let authError as LAError {
            handleAuthError(authError)
            throw mapLAError(authError)
        } catch {
            logAuthAttempt(success: false, reason: reason)
            throw AuthError.authenticationFailed(error)
        }
    }

    /// Create a new LAContext without authentication (for Keychain queries)
    func createContext() -> LAContext {
        return LAContext()
    }

    /// Invalidate authentication context (logout)
    func invalidate(context: LAContext) {
        context.invalidate()
    }

    // MARK: - Error Handling

    private func handleAuthError(_ error: LAError) {
        failedAttempts += 1

        switch error.code {
        case .userCancel, .systemCancel, .appCancel:
            // Don't count cancellations as failed attempts
            failedAttempts = max(0, failedAttempts - 1)

        case .authenticationFailed:
            // Count as failed attempt
            if failedAttempts >= maxFailedAttempts {
                // Lock out for 5 minutes
                lockoutUntil = Date().addingTimeInterval(300)
                logAuthAttempt(success: false, reason: "Max attempts exceeded - lockout initiated")
            }

        default:
            break
        }

        logAuthAttempt(success: false, reason: "LAError: \(error.code.rawValue)")
    }

    private func mapLAError(_ error: LAError) -> AuthError {
        switch error.code {
        case .userCancel, .systemCancel, .appCancel:
            return .userCanceled

        case .biometryNotAvailable:
            return .biometricsNotAvailable

        case .biometryNotEnrolled:
            return .biometricsNotEnrolled

        case .passcodeNotSet:
            return .passcodeNotSet

        case .authenticationFailed:
            if failedAttempts >= maxFailedAttempts {
                return .maxAttemptsExceeded
            }
            return .authenticationFailed(error)

        default:
            return .authenticationFailed(error)
        }
    }

    // MARK: - Lockout Management

    /// Reset failed attempts counter (call after successful auth elsewhere)
    func resetFailedAttempts() {
        failedAttempts = 0
        lockoutUntil = nil
    }

    /// Get remaining failed attempts before lockout
    var remainingAttempts: Int {
        return max(0, maxFailedAttempts - failedAttempts)
    }

    /// Check if currently locked out
    var isLockedOut: Bool {
        if let lockoutUntil = lockoutUntil {
            return Date() < lockoutUntil
        }
        return false
    }

    /// Get remaining lockout time in seconds
    var lockoutRemainingSeconds: Int? {
        guard let lockoutUntil = lockoutUntil else {
            return nil
        }

        let remaining = Int(lockoutUntil.timeIntervalSince(Date()))
        return max(0, remaining)
    }

    // MARK: - Security Audit Logging

    private func logAuthAttempt(success: Bool, reason: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let biometricType = getBiometricType().displayName

        let logEntry = """
        [\(timestamp)] Biometric Authentication:
        - Type: \(biometricType)
        - Success: \(success)
        - Reason: \(reason)
        - Failed Attempts: \(failedAttempts)/\(maxFailedAttempts)
        """

        #if DEBUG
        print(logEntry)
        #endif

        // TODO: Write to secure audit log in production
        // - Encrypt log entries
        // - Implement log rotation
        // - Send critical failures to monitoring system
    }
}

// MARK: - Convenience Methods

extension BiometricAuthManager {

    /// Quick check: Is biometric auth configured and ready?
    var isReady: Bool {
        return isBiometricAvailable() && isPasscodeSet()
    }

    /// Get user-friendly status message
    var statusMessage: String {
        if !isPasscodeSet() {
            return "Device passcode is not set. Please set a passcode in Settings."
        }

        let biometricType = getBiometricType()
        if biometricType == .none {
            return "Biometric authentication is not available on this device."
        }

        // Check if biometrics are enrolled
        let context = LAContext()
        var error: NSError?
        if !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            if error?.code == LAError.biometryNotEnrolled.rawValue {
                return "\(biometricType.displayName) is not set up. Please enroll in Settings."
            }
        }

        return "\(biometricType.displayName) is ready"
    }
}

// MARK: - Testing Support

extension BiometricAuthManager {

    /// Simulate authentication for testing (DO NOT USE IN PRODUCTION!)
    #if DEBUG
    func simulateAuthentication(success: Bool) -> LAContext? {
        if success {
            failedAttempts = 0
            lockoutUntil = nil
            logAuthAttempt(success: true, reason: "SIMULATED")
            return LAContext()
        } else {
            failedAttempts += 1
            logAuthAttempt(success: false, reason: "SIMULATED")
            return nil
        }
    }
    #endif
}
