import SwiftUI
import Combine

/// PIN entry view for unlocking vault
struct PINEntryView: View {
    @Environment(\.dismiss) var dismiss
    @StateObject private var viewModel: PINEntryViewModel
    let onSuccess: () -> Void

    init(onSuccess: @escaping () -> Void) {
        self.onSuccess = onSuccess
        _viewModel = StateObject(wrappedValue: PINEntryViewModel(onSuccess: onSuccess))
    }

    var body: some View {
        VStack(spacing: 30) {
            Spacer()

            // Lock icon
            Image(systemName: "lock.fill")
                .font(.system(size: 70))
                .foregroundColor(.blue)

            VStack(spacing: 10) {
                Text("Enter PIN")
                    .font(.title.bold())

                Text("Unlock your password vault")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            // PIN dots display
            HStack(spacing: 20) {
                ForEach(0..<12, id: \.self) { index in
                    Circle()
                        .fill(index < viewModel.pin.count ? Color.blue : Color.gray.opacity(0.3))
                        .frame(width: 12, height: 12)
                }
            }
            .padding(.vertical)

            // Error message
            if let error = viewModel.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding()
            }

            Spacer()

            // Numeric keypad
            PINKeypadView(
                onNumberTap: { number in
                    viewModel.appendDigit(number)
                },
                onDeleteTap: {
                    viewModel.deleteDigit()
                }
            )

            // Alternative unlock method
            Button(action: {
                dismiss()
                // User can unlock with biometric instead
            }) {
                HStack {
                    Image(systemName: biometricIcon)
                    Text("Use \(biometricName) Instead")
                }
                .foregroundColor(.blue)
            }
            .padding(.bottom)

            Spacer()
        }
        .onChange(of: viewModel.unlockSuccess) { _, success in
            if success {
                dismiss()
            }
        }
    }

    // MARK: - Biometric Info

    private var biometricName: String {
        let biometric = BiometricAuthManager.shared
        return biometric.getBiometricType().displayName
    }

    private var biometricIcon: String {
        let biometric = BiometricAuthManager.shared
        return biometric.getBiometricType().icon
    }
}

// MARK: - ViewModel

@MainActor
class PINEntryViewModel: ObservableObject {
    @Published var pin = ""
    @Published var errorMessage: String?
    @Published var unlockSuccess = false

    private let vaultManager = VaultManager.shared
    private let onSuccess: () -> Void

    init(onSuccess: @escaping () -> Void) {
        self.onSuccess = onSuccess
    }

    func appendDigit(_ digit: Int) {
        guard pin.count < 12 else { return }

        pin.append(String(digit))
        errorMessage = nil

        // Auto-verify when PIN reaches reasonable length
        if pin.count >= 4 {
            Task {
                await verifyPIN()
            }
        }
    }

    func deleteDigit() {
        if !pin.isEmpty {
            pin.removeLast()
            errorMessage = nil
        }
    }

    private func verifyPIN() async {
        // Debounce: wait a bit in case user is still typing
        try? await Task.sleep(nanoseconds: 300_000_000) // 0.3s

        guard !pin.isEmpty else { return }

        do {
            let success = try await vaultManager.unlockVaultWithPIN(pin)

            if success {
                unlockSuccess = true
                onSuccess()
                print("✅ Vault unlocked with PIN")
            }
        } catch {
            errorMessage = "Incorrect PIN"
            print("❌ PIN unlock failed: \(error)")

            // Clear PIN after delay
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            pin = ""
        }
    }
}

// MARK: - Preview

#Preview {
    PINEntryView(onSuccess: {
        print("PIN unlock successful!")
    })
}
