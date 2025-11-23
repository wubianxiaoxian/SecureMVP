import SwiftUI
import Combine

/// PIN management view for changing/disabling PIN
struct PINManagementView: View {
    @Environment(\.dismiss) var dismiss
    @StateObject private var viewModel = PINManagementViewModel()

    var body: some View {
        List {
            Section {
                HStack {
                    Text("Status")
                    Spacer()
                    Text("Enabled")
                        .foregroundColor(.green)
                }
            }

            Section("Options") {
                Button {
                    viewModel.showChangePIN = true
                } label: {
                    Label("Change PIN", systemImage: "arrow.triangle.2.circlepath")
                }

                Button(role: .destructive) {
                    viewModel.showDisablePIN = true
                } label: {
                    Label("Disable PIN", systemImage: "xmark.circle")
                }
            }

            Section {
                Text("PIN authentication provides an alternative way to unlock your vault without using biometrics. Your PIN is secured using PBKDF2-HMAC-SHA256 with 310,000 iterations.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("PIN Authentication")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Disable PIN?", isPresented: $viewModel.showDisablePIN) {
            Button("Disable", role: .destructive) {
                Task {
                    await viewModel.disablePIN()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You will need to use biometric authentication to unlock your vault.")
        }
        .alert("Error", isPresented: $viewModel.showError) {
            Button("OK", role: .cancel) {}
        } message: {
            if let error = viewModel.errorMessage {
                Text(error)
            }
        }
        .sheet(isPresented: $viewModel.showChangePIN) {
            ChangePINView()
        }
        .onChange(of: viewModel.pinDisabled) { _, disabled in
            if disabled {
                dismiss()
            }
        }
    }
}

// MARK: - Change PIN View

struct ChangePINView: View {
    @Environment(\.dismiss) var dismiss
    @StateObject private var viewModel = ChangePINViewModel()

    var body: some View {
        NavigationView {
            VStack(spacing: 30) {
                Spacer()

                // Lock icon
                Image(systemName: "lock.rotation")
                    .font(.system(size: 70))
                    .foregroundColor(.blue)

                VStack(spacing: 10) {
                    Text(viewModel.step.title)
                        .font(.title.bold())

                    Text(viewModel.step.subtitle)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                // PIN dots display
                HStack(spacing: 20) {
                    ForEach(0..<12, id: \.self) { index in
                        Circle()
                            .fill(index < viewModel.pin.count ? Color.blue : Color.gray.opacity(0.3))
                            .frame(width: 12, height: 12)
                            .opacity(index < 12 ? 1 : 0.3)
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
            .onChange(of: viewModel.changeComplete) { _, complete in
                if complete {
                    dismiss()
                }
            }
        }
    }
}

// MARK: - ViewModels

@MainActor
class PINManagementViewModel: ObservableObject {
    @Published var showChangePIN = false
    @Published var showDisablePIN = false
    @Published var showError = false
    @Published var errorMessage: String?
    @Published var pinDisabled = false

    private let vaultManager = VaultManager.shared

    func disablePIN() async {
        do {
            try vaultManager.disablePINAuthentication()
            pinDisabled = true
            print("✅ PIN disabled successfully")
        } catch {
            errorMessage = "Failed to disable PIN: \(error.localizedDescription)"
            showError = true
            print("❌ Failed to disable PIN: \(error)")
        }
    }
}

@MainActor
class ChangePINViewModel: ObservableObject {
    @Published var pin = ""
    @Published var step: Step = .oldPIN
    @Published var errorMessage: String?
    @Published var changeComplete = false

    private var oldPIN = ""
    private var newPIN = ""

    enum Step {
        case oldPIN
        case newPIN
        case confirmPIN

        var title: String {
            switch self {
            case .oldPIN: return "Enter Current PIN"
            case .newPIN: return "Enter New PIN"
            case .confirmPIN: return "Confirm New PIN"
            }
        }

        var subtitle: String {
            switch self {
            case .oldPIN: return "Verify your current PIN"
            case .newPIN: return "Enter a 4-12 digit PIN"
            case .confirmPIN: return "Re-enter your new PIN"
            }
        }
    }

    func appendDigit(_ digit: Int) {
        guard pin.count < 12 else { return }

        pin.append(String(digit))
        errorMessage = nil

        // Auto-progress when PIN reaches reasonable length
        if step == .oldPIN && pin.count >= 4 {
            Task {
                await verifyOldPIN()
            }
        } else if step == .confirmPIN && pin.count == newPIN.count {
            Task {
                await confirmNewPIN()
            }
        }
    }

    func deleteDigit() {
        if !pin.isEmpty {
            pin.removeLast()
            errorMessage = nil
        }
    }

    private func verifyOldPIN() async {
        // Debounce
        try? await Task.sleep(nanoseconds: 300_000_000)

        guard !pin.isEmpty else { return }

        do {
            let pinManager = PINManager.shared
            let isValid = try pinManager.verifyPIN(pin)

            if isValid {
                oldPIN = pin
                pin = ""
                step = .newPIN
                errorMessage = nil
            }
        } catch {
            errorMessage = "Incorrect PIN"
            try? await Task.sleep(nanoseconds: 500_000_000)
            pin = ""
        }
    }

    private func confirmNewPIN() async {
        guard pin == newPIN else {
            errorMessage = "PINs do not match"
            try? await Task.sleep(nanoseconds: 500_000_000)
            pin = ""
            newPIN = ""
            step = .newPIN
            return
        }

        // Change PIN
        do {
            let pinManager = PINManager.shared
            try pinManager.changePIN(oldPIN: oldPIN, newPIN: newPIN)
            changeComplete = true
            print("✅ PIN changed successfully")
        } catch {
            errorMessage = "Failed to change PIN: \(error.localizedDescription)"
            pin = ""
            oldPIN = ""
            newPIN = ""
            step = .oldPIN
        }
    }

    func nextStep() {
        switch step {
        case .oldPIN:
            Task { await verifyOldPIN() }
        case .newPIN:
            // Validate new PIN
            if pin.count < 4 {
                errorMessage = "PIN must be at least 4 digits"
                return
            }

            let pinManager = PINManager.shared
            let strength = pinManager.estimatePINStrength(pin)
            if strength == .veryWeak {
                errorMessage = "PIN is too weak"
                return
            }

            newPIN = pin
            pin = ""
            step = .confirmPIN
            errorMessage = nil

        case .confirmPIN:
            Task { await confirmNewPIN() }
        }
    }
}

// MARK: - Preview

#Preview {
    NavigationView {
        PINManagementView()
    }
}
