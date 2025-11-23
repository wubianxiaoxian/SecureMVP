import SwiftUI
import Combine

/// Security dashboard showing vault health and Sentinel insights
struct SecurityDashboardView: View {
    @StateObject private var viewModel = SecurityDashboardViewModel()

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Vault Status Card
                    statusCard

                    // Sentinel AI Stats
                    sentinelCard

                    // Security Metrics
                    metricsCard

                    // Key Rotation Status
                    keyRotationCard
                }
                .padding()
            }
            .navigationTitle("Security Dashboard")
            .task {
                await viewModel.loadData()
            }
            .refreshable {
                await viewModel.loadData()
            }
        }
    }

    // MARK: - Vault Status

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Image(systemName: viewModel.isUnlocked ? "lock.open.fill" : "lock.fill")
                    .font(.title2)
                    .foregroundColor(viewModel.isUnlocked ? .green : .blue)

                Text("Vault Status")
                    .font(.headline)

                Spacer()

                Text(viewModel.isUnlocked ? "🔓 Unlocked" : "🔒 Locked")
                    .font(.subheadline)
                    .foregroundColor(viewModel.isUnlocked ? .green : .secondary)
            }

            Divider()

            InfoRow(label: "Total Credentials", value: "\(viewModel.stats?.totalCredentials ?? 0)")
            InfoRow(label: "Vault Version", value: "v\(viewModel.stats?.currentVersion ?? 1)")
            InfoRow(label: "Last Modified", value: formatDate(viewModel.stats?.lastModified))
        }
        .cardStyle()
    }

    // MARK: - Sentinel AI

    private var sentinelCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Image(systemName: "brain.head.profile")
                    .font(.title2)
                    .foregroundColor(.purple)

                Text("Sentinel AI")
                    .font(.headline)

                Spacer()

                Text("v1.0")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Divider()

            if viewModel.isLearningMode {
                HStack {
                    Image(systemName: "graduationcap.fill")
                        .foregroundColor(.orange)
                    Text("Learning Mode")
                        .font(.subheadline)
                    Spacer()
                    Text("\(viewModel.learningDaysRemaining) days remaining")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(12)
                .background(Color.orange.opacity(0.1))
                .cornerRadius(8)
            } else {
                HStack {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(.green)
                    Text("Active Protection")
                        .font(.subheadline)
                    Spacer()
                }
                .padding(12)
                .background(Color.green.opacity(0.1))
                .cornerRadius(8)
            }

            InfoRow(label: "Monitored Credentials", value: "\(viewModel.monitoredCredentials)")
            InfoRow(label: "Trust Decisions Today", value: "\(viewModel.trustDecisionsToday)")
        }
        .cardStyle()
    }

    // MARK: - Security Metrics

    private var metricsCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Image(systemName: "chart.bar.fill")
                    .font(.title2)
                    .foregroundColor(.blue)

                Text("Security Metrics")
                    .font(.headline)
            }

            Divider()

            MetricRow(
                icon: "shield.checkered",
                label: "Encryption",
                value: "AES-256-GCM",
                color: .green
            )

            MetricRow(
                icon: "cpu.fill",
                label: "Secure Enclave",
                value: viewModel.secureEnclaveAvailable ? "Active" : "Unavailable",
                color: viewModel.secureEnclaveAvailable ? .green : .orange
            )

            MetricRow(
                icon: viewModel.biometricIcon,
                label: viewModel.biometricType,
                value: viewModel.biometricStatus,
                color: viewModel.biometricStatus == "Ready" ? .green : .red
            )
        }
        .cardStyle()
    }

    // MARK: - Key Rotation

    private var keyRotationCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.title2)
                    .foregroundColor(viewModel.isRotationDue ? .orange : .green)

                Text("Key Rotation")
                    .font(.headline)

                Spacer()

                if viewModel.isRotationDue {
                    Button(action: {
                        Task {
                            await viewModel.rotateKeys()
                        }
                    }) {
                        Text("Rotate Now")
                            .font(.caption.bold())
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(Color.orange)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                    }
                }
            }

            Divider()

            if let lastRotation = viewModel.stats?.lastKeyRotation {
                InfoRow(label: "Last Rotation", value: formatDate(lastRotation))
            } else {
                InfoRow(label: "Last Rotation", value: "Never")
            }

            InfoRow(label: "Rotation Interval", value: "90 days")
            InfoRow(
                label: "Status",
                value: viewModel.isRotationDue ? "⚠️ Due for rotation" : "✅ Up to date"
            )
        }
        .cardStyle()
    }

    // MARK: - Helpers

    private func formatDate(_ date: Date?) -> String {
        guard let date = date else { return "N/A" }

        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - View Model

@MainActor
class SecurityDashboardViewModel: ObservableObject {
    @Published var stats: VaultStats?
    @Published var isUnlocked = false
    @Published var isRotationDue = false
    @Published var isLearningMode = true
    @Published var learningDaysRemaining = 14
    @Published var monitoredCredentials = 0
    @Published var trustDecisionsToday = 0

    @Published var secureEnclaveAvailable = false
    @Published var biometricType = "Face ID"
    @Published var biometricIcon = "faceid"
    @Published var biometricStatus = "Ready"

    private let vaultManager = VaultManager.shared
    private let secureEnclave = SecureEnclaveManager.shared
    private let biometric = BiometricAuthManager.shared

    func loadData() async {
        // Load vault stats
        if let vaultStats = try? vaultManager.getVaultStats() {
            stats = vaultStats
            isUnlocked = vaultStats.isUnlocked
            isRotationDue = vaultStats.isRotationDue
        }

        // Check Secure Enclave
        secureEnclaveAvailable = secureEnclave.isSecureEnclaveAvailable()

        // Check biometrics
        let bioType = biometric.getBiometricType()
        biometricType = bioType.displayName
        biometricIcon = bioType.icon
        biometricStatus = biometric.statusMessage.contains("ready") ? "Ready" : "Not Ready"

        // TODO: Load Sentinel stats
        monitoredCredentials = stats?.totalCredentials ?? 0
        trustDecisionsToday = 0 // Implement tracking
    }

    func rotateKeys() async {
        do {
            try await vaultManager.rotateVaultKey()
            await loadData()
        } catch {
            print("Key rotation failed: \(error)")
        }
    }
}

// MARK: - Reusable Components

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.bold())
        }
    }
}

struct MetricRow: View {
    let icon: String
    let label: String
    let value: String
    let color: Color

    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(color)
                .frame(width: 30)

            Text(label)
                .font(.subheadline)

            Spacer()

            Text(value)
                .font(.subheadline.bold())
                .foregroundColor(color)
        }
    }
}

// MARK: - Card Style Modifier

extension View {
    func cardStyle() -> some View {
        self
            .padding()
            .background(Color(.systemBackground))
            .cornerRadius(12)
            .shadow(color: Color.black.opacity(0.1), radius: 5, x: 0, y: 2)
    }
}
