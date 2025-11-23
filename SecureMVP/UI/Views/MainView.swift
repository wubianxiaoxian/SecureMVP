import SwiftUI
import Combine

/// Main application view with tab navigation
struct MainView: View {
    @StateObject private var viewModel = MainViewModel()

    var body: some View {
        TabView {
            VaultView()
                .tabItem {
                    Label("Vault", systemImage: "lock.shield")
                }

            SecurityDashboardView()
                .tabItem {
                    Label("Security", systemImage: "chart.bar.fill")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gearshape.fill")
                }
        }
        .task {
            await viewModel.initializeApp()
        }
        .alert("Welcome to SecureMVP", isPresented: $viewModel.showWelcome) {
            Button("Set Up Vault") {
                Task {
                    await viewModel.setupVault()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Create your secure password vault with hardware-backed encryption.")
        }
        .alert("Error", isPresented: $viewModel.showError) {
            Button("OK") {}
        } message: {
            Text(viewModel.errorMessage)
        }
    }
}

/// Main view model coordinating app initialization
@MainActor
class MainViewModel: ObservableObject {
    @Published var showWelcome = false
    @Published var showError = false
    @Published var errorMessage = ""

    private let vaultManager = VaultManager.shared

    func initializeApp() async {
        // Check if vault is initialized
        if !vaultManager.isVaultInitialized() {
            showWelcome = true
        }
    }

    func setupVault() async {
        print("📱 ENTRY: MainViewModel.setupVault() called")
        print("📍 Thread: \(Thread.current)")
        print("📍 Is main thread: \(Thread.isMainThread)")

        do {
            print("📱 MainViewModel: Starting vault setup...")
            print("📱 Calling vaultManager.initializeVault()...")

            try await vaultManager.initializeVault()

            print("✅ MainViewModel: Vault setup complete")
            print("🔍 Verifying vault initialization...")
            let isInitialized = vaultManager.isVaultInitialized()
            print("📊 Vault initialized check: \(isInitialized)")

        } catch {
            print("❌ MainViewModel: Vault setup failed")
            print("❌ Error type: \(type(of: error))")
            print("❌ Error: \(error)")
            print("❌ Localized description: \(error.localizedDescription)")

            if let vaultError = error as? VaultManager.VaultError {
                print("❌ VaultError details: \(vaultError)")
            }

            errorMessage = error.localizedDescription
            showError = true
        }

        print("📱 EXIT: MainViewModel.setupVault()")
    }
}
