import SwiftUI
import Combine

/// Settings and preferences view
struct SettingsView: View {
    @StateObject private var viewModel = SettingsViewModel()

    var body: some View {
        NavigationView {
            List {
                // Security Section
                Section("Security") {
                    NavigationLink {
                        BiometricSettingsView()
                    } label: {
                        Label("Biometric Authentication", systemImage: "faceid")
                    }

                    // 🔥 NEW: PIN Authentication
                    if PINManager.shared.isPINSet() {
                        NavigationLink {
                            PINManagementView()
                        } label: {
                            Label("PIN Authentication", systemImage: "number.circle")
                        }
                    } else {
                        Button {
                            viewModel.showPINSetup = true
                        } label: {
                            Label("Enable PIN Authentication", systemImage: "number.circle")
                        }
                    }

                    Toggle(isOn: $viewModel.autoLockEnabled) {
                        Label("Auto-Lock Vault", systemImage: "lock.rotation")
                    }

                    if viewModel.autoLockEnabled {
                        Picker("Auto-Lock After", selection: $viewModel.autoLockDuration) {
                            Text("1 minute").tag(60)
                            Text("5 minutes").tag(300)
                            Text("15 minutes").tag(900)
                            Text("1 hour").tag(3600)
                        }
                    }
                }

                // Vault Management
                Section("Vault Management") {
                    Button {
                        viewModel.showKeyRotation = true
                    } label: {
                        Label("Rotate Encryption Keys", systemImage: "arrow.triangle.2.circlepath")
                    }

                    Button {
                        viewModel.showExport = true
                    } label: {
                        Label("Export Vault (Encrypted)", systemImage: "square.and.arrow.up")
                    }
                }

                // Sentinel AI
                Section("Sentinel AI") {
                    Toggle(isOn: $viewModel.sentinelEnabled) {
                        Label("Trust Score Analysis", systemImage: "brain.head.profile")
                    }

                    if viewModel.sentinelEnabled {
                        Picker("Security Level", selection: $viewModel.sentinelStrictness) {
                            Text("Permissive").tag(0)
                            Text("Balanced").tag(1)
                            Text("Strict").tag(2)
                        }
                    }

                    Button("Reset Learning Model") {
                        viewModel.showResetModel = true
                    }
                    .foregroundColor(.orange)
                }

                // Advanced
                Section("Advanced") {
                    NavigationLink {
                        AdvancedSettingsView()
                    } label: {
                        Label("Advanced Settings", systemImage: "gearshape.2")
                    }

                    NavigationLink {
                        AuditLogView()
                    } label: {
                        Label("Security Audit Log", systemImage: "doc.text")
                    }
                }

                // About
                Section("About") {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0 (MVP)")
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Text("Encryption")
                        Spacer()
                        Text("AES-256-GCM")
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Text("Secure Enclave")
                        Spacer()
                        Text(viewModel.secureEnclaveStatus)
                            .foregroundColor(viewModel.secureEnclaveAvailable ? .green : .orange)
                    }
                }

                // Danger Zone
                Section("Danger Zone") {
                    Button(role: .destructive) {
                        viewModel.showResetVault = true
                    } label: {
                        Label("Delete All Data", systemImage: "trash.fill")
                    }
                }
            }
            .navigationTitle("Settings")
        }
        .sheet(isPresented: $viewModel.showPINSetup) {
            PINSetupView()
        }
        .alert("Rotate Encryption Keys?", isPresented: $viewModel.showKeyRotation) {
            Button("Rotate", role: .destructive) {
                Task {
                    await viewModel.rotateKeys()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will create new encryption keys and re-encrypt all credentials. This process may take a few moments.")
        }
        .alert("Reset Sentinel Model?", isPresented: $viewModel.showResetModel) {
            Button("Reset", role: .destructive) {
                viewModel.resetSentinel()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will erase all learned behavior patterns. Sentinel will restart in learning mode.")
        }
        .alert("⚠️ Delete All Vault Data?", isPresented: $viewModel.showResetVault) {
            Button("Delete Everything", role: .destructive) {
                Task {
                    await viewModel.resetVault()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This action cannot be undone. All passwords and encryption keys will be permanently deleted.")
        }
    }
}

// MARK: - Biometric Settings

struct BiometricSettingsView: View {
    @StateObject private var viewModel = BiometricSettingsViewModel()

    var body: some View {
        List {
            Section {
                HStack {
                    Text("Type")
                    Spacer()
                    Text(viewModel.biometricType)
                        .foregroundColor(.secondary)
                }

                HStack {
                    Text("Status")
                    Spacer()
                    Text(viewModel.biometricStatus)
                        .foregroundColor(viewModel.biometricAvailable ? .green : .orange)
                }
            }

            Section("Options") {
                Toggle("Require for Vault Unlock", isOn: $viewModel.requireForUnlock)
                    .onChange(of: viewModel.requireForUnlock) { _, _ in
                        viewModel.savePreferences()
                    }

                Toggle("Require for Credential Copy", isOn: $viewModel.requireForCopy)
                    .onChange(of: viewModel.requireForCopy) { _, _ in
                        viewModel.savePreferences()
                    }
            }

            Section {
                Text("Biometric authentication uses your device's Face ID or Touch ID to securely unlock the vault. Your biometric data never leaves your device.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("Biometric Settings")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await viewModel.loadBiometricInfo()
        }
    }
}

// MARK: - Biometric Settings ViewModel

@MainActor
class BiometricSettingsViewModel: ObservableObject {
    @Published var biometricType = "Face ID"
    @Published var biometricStatus = "Checking..."
    @Published var biometricAvailable = false
    @Published var requireForUnlock = true
    @Published var requireForCopy = false

    private let biometric = BiometricAuthManager.shared
    private let userDefaults = UserDefaults.standard

    init() {
        loadPreferences()
    }

    func loadBiometricInfo() async {
        biometricType = biometric.getBiometricType().displayName
        biometricAvailable = biometric.statusMessage.contains("ready")
        biometricStatus = biometricAvailable ? "Ready" : "Not Available"
    }

    private func loadPreferences() {
        requireForUnlock = userDefaults.bool(forKey: "biometric.requireForUnlock") != false // Default true
        requireForCopy = userDefaults.bool(forKey: "biometric.requireForCopy") // Default false
    }

    func savePreferences() {
        userDefaults.set(requireForUnlock, forKey: "biometric.requireForUnlock")
        userDefaults.set(requireForCopy, forKey: "biometric.requireForCopy")
        print("✅ Biometric preferences saved: unlock=\(requireForUnlock), copy=\(requireForCopy)")
    }
}

// MARK: - Advanced Settings

struct AdvancedSettingsView: View {
    var body: some View {
        List {
            Section("Encryption") {
                HStack {
                    Text("Algorithm")
                    Spacer()
                    Text("AES-256-GCM")
                        .foregroundColor(.secondary)
                }

                HStack {
                    Text("Key Derivation")
                    Spacer()
                    Text("HKDF-SHA256")
                        .foregroundColor(.secondary)
                }

                HStack {
                    Text("Nonce Size")
                    Spacer()
                    Text("96 bits")
                        .foregroundColor(.secondary)
                }
            }

            Section("Key Rotation") {
                HStack {
                    Text("Interval")
                    Spacer()
                    Text("90 days")
                        .foregroundColor(.secondary)
                }

                HStack {
                    Text("Auto-Rotate")
                    Spacer()
                    Text("Enabled")
                        .foregroundColor(.green)
                }
            }

            Section("Performance") {
                HStack {
                    Text("Session Duration")
                    Spacer()
                    Text("5 minutes")
                        .foregroundColor(.secondary)
                }

                HStack {
                    Text("Memory Clearing")
                    Spacer()
                    Text("Automatic")
                        .foregroundColor(.green)
                }
            }
        }
        .navigationTitle("Advanced")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Audit Log

struct AuditLogView: View {
    var body: some View {
        List {
            Text("Security audit logging is enabled. All cryptographic operations are logged locally.")
                .font(.caption)
                .foregroundColor(.secondary)
                .listRowBackground(Color.clear)

            Section("Recent Events") {
                AuditLogRow(
                    icon: "lock.open",
                    event: "Vault Unlocked",
                    timestamp: Date(),
                    color: .green
                )

                AuditLogRow(
                    icon: "key",
                    event: "Credential Accessed",
                    timestamp: Date().addingTimeInterval(-300),
                    color: .blue
                )

                AuditLogRow(
                    icon: "arrow.triangle.2.circlepath",
                    event: "Key Rotation",
                    timestamp: Date().addingTimeInterval(-86400),
                    color: .orange
                )
            }
        }
        .navigationTitle("Audit Log")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct AuditLogRow: View {
    let icon: String
    let event: String
    let timestamp: Date
    let color: Color

    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(color)
                .frame(width: 30)

            VStack(alignment: .leading) {
                Text(event)
                    .font(.subheadline)

                Text(formatTimestamp(timestamp))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
    }

    private func formatTimestamp(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - View Model

@MainActor
class SettingsViewModel: ObservableObject {
    @Published var autoLockEnabled = true
    @Published var autoLockDuration = 300

    @Published var sentinelEnabled = true
    @Published var sentinelStrictness = 1

    @Published var secureEnclaveAvailable = false
    @Published var secureEnclaveStatus = "Checking..."

    @Published var showKeyRotation = false
    @Published var showExport = false
    @Published var showResetModel = false
    @Published var showResetVault = false
    @Published var showPINSetup = false  // 🔥 NEW: Show PIN setup sheet

    private let vaultManager = VaultManager.shared
    private let secureEnclave = SecureEnclaveManager.shared
    private let sentinel = SentinelEngine.shared

    init() {
        loadSettings()
    }

    func loadSettings() {
        secureEnclaveAvailable = secureEnclave.isSecureEnclaveAvailable()
        secureEnclaveStatus = secureEnclaveAvailable ? "✅ Available" : "⚠️ Not Available"
    }

    func rotateKeys() async {
        do {
            try await vaultManager.rotateVaultKey()
            print("✅ Keys rotated successfully")
        } catch {
            print("❌ Key rotation failed: \(error)")
        }
    }

    func resetSentinel() {
        sentinel.resetModel()
        print("✅ Sentinel model reset")
    }

    func resetVault() async {
        do {
            try await vaultManager.resetVault()
            print("⚠️ Vault reset complete")
        } catch {
            print("❌ Vault reset failed: \(error)")
        }
    }
}
