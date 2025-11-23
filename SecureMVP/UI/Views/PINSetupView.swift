import SwiftUI
import Combine

/// PIN setup view for initial PIN creation
struct PINSetupView: View {
    @Environment(\.dismiss) var dismiss
    @StateObject private var viewModel = PINSetupViewModel()

    var body: some View {
        NavigationView {
            VStack(spacing: 30) {
                Spacer()

                // Lock icon
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 70))
                    .foregroundColor(.blue)

                VStack(spacing: 10) {
                    Text(viewModel.mode == .setup ? "Create PIN" : "Confirm PIN")
                        .font(.title.bold())

                    Text(viewModel.mode == .setup ? "Enter a 4-12 digit PIN" : "Re-enter your PIN")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                // PIN dots display
                HStack(spacing: 20) {
                    ForEach(0..<12, id: \.self) { index in
                        Circle()
                            .fill(index < viewModel.pin.count ? Color.blue : Color.gray.opacity(0.3))
                            .frame(width: 12, height: 12)
                            .opacity(index < (viewModel.mode == .setup ? 12 : viewModel.setupPin.count) ? 1 : 0.3)
                    }
                }
                .padding(.vertical)

                // PIN strength indicator (only during setup)
                if viewModel.mode == .setup && !viewModel.pin.isEmpty {
                    let strength = PINManager.shared.estimatePINStrength(viewModel.pin)
                    HStack {
                        Text(strength.emoji)
                        Text(strength.description)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

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

                Spacer()
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
            .onChange(of: viewModel.setupComplete) { _, complete in
                if complete {
                    dismiss()
                }
            }
        }
    }
}

// MARK: - ViewModel

@MainActor
class PINSetupViewModel: ObservableObject {
    @Published var pin = ""
    @Published var setupPin = ""  // First PIN entry
    @Published var mode: SetupMode = .setup
    @Published var errorMessage: String?
    @Published var setupComplete = false

    private let vaultManager = VaultManager.shared

    enum SetupMode {
        case setup     // First entry
        case confirm   // Confirmation entry
    }

    func appendDigit(_ digit: Int) {
        guard pin.count < 12 else { return }

        pin.append(String(digit))
        errorMessage = nil

        // Auto-progress when PIN reaches minimum length
        if mode == .setup && pin.count >= 4 {
            // Allow user to continue typing or press enter
        } else if mode == .confirm && pin.count == setupPin.count {
            // Auto-verify when confirmation reaches same length
            Task {
                await confirmPIN()
            }
        }
    }

    func deleteDigit() {
        if !pin.isEmpty {
            pin.removeLast()
            errorMessage = nil
        }
    }

    func nextStep() {
        if mode == .setup {
            // Validate PIN
            do {
                let pinManager = PINManager.shared
                if pin.count < 4 {
                    errorMessage = "PIN must be at least 4 digits"
                    return
                }

                // Check strength
                let strength = pinManager.estimatePINStrength(pin)
                if strength == .veryWeak {
                    errorMessage = "PIN is too weak - avoid repeating or sequential numbers"
                    return
                }

                // Move to confirmation
                setupPin = pin
                pin = ""
                mode = .confirm
                errorMessage = nil
            }
        }
    }

    private func confirmPIN() async {
        guard mode == .confirm else { return }

        // Check if PINs match
        guard pin == setupPin else {
            errorMessage = "PINs do not match"
            // Reset to setup mode
            pin = ""
            setupPin = ""
            mode = .setup
            return
        }

        // Enable PIN authentication
        do {
            try await vaultManager.enablePINAuthentication(pin: pin)
            setupComplete = true
            print("✅ PIN setup complete")
        } catch {
            errorMessage = "Failed to enable PIN: \(error.localizedDescription)"
            pin = ""
            setupPin = ""
            mode = .setup
        }
    }
}

// MARK: - Preview

#Preview {
    PINSetupView()
}
