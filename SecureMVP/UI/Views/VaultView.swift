import SwiftUI
import Combine

/// Main vault view showing credentials and unlock interface
struct VaultView: View {
    @StateObject private var viewModel = VaultViewModel()

    var body: some View {
        NavigationView {
            Group {
                if viewModel.isUnlocked {
                    credentialsList
                } else {
                    lockedView
                }
            }
            .navigationTitle("Password Vault")
            .onChange(of: viewModel.isUnlocked) { oldValue, newValue in
                print("🔄 VaultView: isUnlocked changed \(oldValue) → \(newValue)")
            }
            .toolbar {
                if viewModel.isUnlocked {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button(action: { viewModel.showAddCredential = true }) {
                            Image(systemName: "plus.circle.fill")
                                .font(.title2)
                        }
                    }

                    ToolbarItem(placement: .navigationBarLeading) {
                        Button(action: { viewModel.lockVault() }) {
                            Image(systemName: "lock.fill")
                        }
                    }
                }
            }
            .sheet(isPresented: $viewModel.showAddCredential) {
                AddCredentialView(viewModel: viewModel)
            }
            .sheet(isPresented: $viewModel.showPINEntry) {
                PINEntryView(onSuccess: {
                    Task {
                        await viewModel.onPINUnlockSuccess()
                    }
                })
            }
        }
    }

    // MARK: - Locked State

    private var lockedView: some View {
        VStack(spacing: 30) {
            Spacer()

            Image(systemName: "lock.shield.fill")
                .font(.system(size: 80))
                .foregroundColor(.blue)

            VStack(spacing: 10) {
                Text("Vault Locked")
                    .font(.title.bold())

                Text("Unlock to access your passwords")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Button(action: {
                print("🔓 Unlock button tapped")
                Task {
                    await viewModel.unlockVault()
                }
            }) {
                HStack {
                    Image(systemName: biometricIcon)
                    Text("Unlock with \(biometricName)")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(12)
            }
            .padding(.horizontal, 40)

            // 🔥 NEW: PIN unlock option
            if PINManager.shared.isPINSet() {
                Button(action: {
                    print("🔐 PIN unlock tapped")
                    viewModel.showPINEntry = true
                }) {
                    HStack {
                        Image(systemName: "number.circle")
                        Text("Unlock with PIN")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.secondary.opacity(0.2))
                    .foregroundColor(.primary)
                    .cornerRadius(12)
                }
                .padding(.horizontal, 40)
            }

            // 🔥 DEBUG: Show current state
            if viewModel.errorMessage != nil {
                Text("Error: \(viewModel.errorMessage ?? "")")
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding()
            }

            Spacer()
        }
        .padding()
    }

    // MARK: - Unlocked State

    private var credentialsList: some View {
        List {
            // 🔥 NEW: Search bar
            if !viewModel.credentials.isEmpty {
                Section {
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.secondary)
                        TextField("Search credentials...", text: $viewModel.searchQuery)
                            .textFieldStyle(PlainTextFieldStyle())
                            .autocapitalization(.none)
                    }
                    .padding(.vertical, 4)
                }
            }

            if viewModel.credentials.isEmpty {
                VStack(spacing: 20) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)

                    Text("No Passwords Yet")
                        .font(.title3)
                        .foregroundColor(.secondary)

                    Text("Tap + to add your first password")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 60)
                .listRowBackground(Color.clear)
            } else if viewModel.filteredCredentials.isEmpty {
                // 🔥 NEW: Show "no results" when search yields nothing
                VStack(spacing: 20) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)

                    Text("No Results")
                        .font(.title3)
                        .foregroundColor(.secondary)

                    Text("Try a different search term")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 60)
                .listRowBackground(Color.clear)
            } else {
                // 🔥 UPDATED: Use filteredCredentials instead of credentials
                ForEach(viewModel.filteredCredentials) { credential in
                    CredentialRow(credential: credential) {
                        Task {
                            await viewModel.copyPassword(for: credential)
                        }
                    } onEdit: {
                        // 🔥 NEW: Edit action
                        viewModel.editingCredential = credential
                        viewModel.showEditCredential = true
                    }
                }
                .onDelete(perform: deleteFilteredCredentials)
            }
        }
        .sheet(isPresented: $viewModel.showEditCredential) {
            if let credential = viewModel.editingCredential {
                EditCredentialView(credential: credential, viewModel: viewModel)
            }
        }
    }

    // 🔥 NEW: Handle deletion from filtered list
    private func deleteFilteredCredentials(at offsets: IndexSet) {
        // Map filtered indices back to original credentials array
        let credentialsToDelete = offsets.map { viewModel.filteredCredentials[$0] }
        let originalIndices = credentialsToDelete.compactMap { credential in
            viewModel.credentials.firstIndex(where: { $0.id == credential.id })
        }
        viewModel.deleteCredentials(at: IndexSet(originalIndices))
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

// MARK: - Credential Row

struct CredentialRow: View {
    let credential: Credential
    let onCopy: () -> Void
    let onEdit: () -> Void  // 🔥 NEW: Edit callback

    @State private var showPassword = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "globe")
                    .foregroundColor(.blue)

                Text(credential.domain)
                    .font(.headline)

                Spacer()

                // 🔥 NEW: Edit button
                Button(action: onEdit) {
                    Image(systemName: "pencil")
                        .foregroundColor(.orange)
                }
                .buttonStyle(BorderlessButtonStyle())

                Button(action: onCopy) {
                    Image(systemName: "doc.on.doc")
                        .foregroundColor(.blue)
                }
                .buttonStyle(BorderlessButtonStyle())
            }

            HStack {
                Image(systemName: "person.fill")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Text(credential.username)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            if let notes = credential.notes, !notes.isEmpty {
                Text(notes)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Add Credential Sheet

struct AddCredentialView: View {
    @ObservedObject var viewModel: VaultViewModel
    @Environment(\.dismiss) var dismiss

    @State private var domain = ""
    @State private var username = ""
    @State private var password = ""
    @State private var notes = ""
    @State private var showPassword = false

    var body: some View {
        NavigationView {
            Form {
                Section("Website or App") {
                    TextField("example.com", text: $domain)
                        .textContentType(.URL)
                        .autocapitalization(.none)
                }

                Section("Credentials") {
                    TextField("Username or Email", text: $username)
                        .textContentType(.username)
                        .autocapitalization(.none)

                    HStack {
                        if showPassword {
                            TextField("Password", text: $password)
                                .textContentType(.password)
                        } else {
                            SecureField("Password", text: $password)
                                .textContentType(.password)
                        }

                        Button(action: { showPassword.toggle() }) {
                            Image(systemName: showPassword ? "eye.slash" : "eye")
                                .foregroundColor(.gray)
                        }
                    }

                    Button("Generate Strong Password") {
                        password = generatePassword()
                    }
                }

                Section("Notes (Optional)") {
                    TextEditor(text: $notes)
                        .frame(height: 100)
                }
            }
            .navigationTitle("Add Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        Task {
                            await saveCredential()
                        }
                    }
                    .disabled(domain.isEmpty || username.isEmpty || password.isEmpty)
                }
            }
        }
    }

    private func saveCredential() async {
        let credential = Credential(
            domain: domain,
            username: username,
            password: password,
            notes: notes.isEmpty ? nil : notes
        )

        await viewModel.addCredential(credential)
        dismiss()
    }

    private func generatePassword() -> String {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return String((0..<20).map { _ in chars.randomElement()! })
    }
}

// MARK: - Edit Credential Sheet

struct EditCredentialView: View {
    let credential: Credential
    @ObservedObject var viewModel: VaultViewModel
    @Environment(\.dismiss) var dismiss

    @State private var username: String
    @State private var password: String
    @State private var notes: String
    @State private var showPassword = false

    init(credential: Credential, viewModel: VaultViewModel) {
        self.credential = credential
        self.viewModel = viewModel
        _username = State(initialValue: credential.username)
        _password = State(initialValue: credential.password)
        _notes = State(initialValue: credential.notes ?? "")
    }

    var body: some View {
        NavigationView {
            Form {
                Section("Website or App") {
                    HStack {
                        Image(systemName: "globe")
                            .foregroundColor(.secondary)
                        Text(credential.domain)
                            .foregroundColor(.secondary)
                    }
                }

                Section("Credentials") {
                    TextField("Username or Email", text: $username)
                        .textContentType(.username)
                        .autocapitalization(.none)

                    HStack {
                        if showPassword {
                            TextField("Password", text: $password)
                                .textContentType(.password)
                        } else {
                            SecureField("Password", text: $password)
                                .textContentType(.password)
                        }

                        Button(action: { showPassword.toggle() }) {
                            Image(systemName: showPassword ? "eye.slash" : "eye")
                                .foregroundColor(.gray)
                        }
                    }

                    Button("Generate New Password") {
                        password = generatePassword()
                    }
                }

                Section("Notes (Optional)") {
                    TextEditor(text: $notes)
                        .frame(height: 100)
                }
            }
            .navigationTitle("Edit Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        Task {
                            await updateCredential()
                        }
                    }
                    .disabled(username.isEmpty || password.isEmpty)
                }
            }
        }
    }

    private func updateCredential() async {
        // Only update if values changed
        let newUsername = username != credential.username ? username : nil
        let newPassword = password != credential.password ? password : nil
        let newNotes = notes != (credential.notes ?? "") ? notes : nil

        await viewModel.updateCredential(
            id: credential.id,
            newPassword: newPassword,
            newUsername: newUsername,
            newNotes: newNotes
        )
        dismiss()
    }

    private func generatePassword() -> String {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return String((0..<20).map { _ in chars.randomElement()! })
    }
}

// MARK: - View Model

@MainActor
class VaultViewModel: ObservableObject {
    @Published var isUnlocked = false
    @Published var credentials: [Credential] = []
    @Published var showAddCredential = false
    @Published var showEditCredential = false
    @Published var editingCredential: Credential?
    @Published var searchQuery = ""
    @Published var errorMessage: String?
    @Published var showPINEntry = false  // 🔥 NEW: Show PIN entry sheet

    private let vaultManager = VaultManager.shared

    // 🔥 NEW: Filtered credentials based on search query
    var filteredCredentials: [Credential] {
        if searchQuery.isEmpty {
            return credentials
        }

        return credentials.filter { credential in
            credential.domain.localizedCaseInsensitiveContains(searchQuery) ||
            credential.username.localizedCaseInsensitiveContains(searchQuery) ||
            (credential.notes?.localizedCaseInsensitiveContains(searchQuery) ?? false)
        }
    }

    init() {
        updateLockState()
        print("📱 VaultViewModel initialized - isUnlocked: \(isUnlocked), vaultInitialized: \(vaultManager.isVaultInitialized())")
    }

    func unlockVault() async {
        do {
            try await vaultManager.unlockVault()

            // 🔥 CRITICAL FIX: Ensure UI update on main thread
            await MainActor.run {
                updateLockState()
                print("🔓 UI: isUnlocked = \(isUnlocked)")
            }

            await loadCredentials()  // 🔥 Fixed: Make async
        } catch {
            await MainActor.run {
                errorMessage = error.localizedDescription
                print("❌ Unlock error: \(error)")
            }
        }
    }

    func lockVault() {
        vaultManager.lockVault()
        updateLockState()
        credentials = []
    }

    func addCredential(_ credential: Credential) async {
        do {
            try await vaultManager.saveCredential(credential)
            await loadCredentials()  // 🔥 Fixed: Make async
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func copyPassword(for credential: Credential) async {
        do {
            let password = try await vaultManager.retrieveCredential(id: credential.id)

            #if os(iOS)
            UIPasteboard.general.string = password
            #endif

            // Calculate trust score
            let request = SentinelEngine.createAccessRequest(
                credentialID: credential.id,
                domain: credential.domain
            )
            let trustScore = SentinelEngine.shared.calculateTrustScore(for: request)

            print("🔐 Password copied - Trust Score: \(trustScore.level.emoji) \(String(format: "%.2f", trustScore.score))")
            print("   Reasoning: \(trustScore.reasoning.joined(separator: ", "))")

            // Record successful access
            SentinelEngine.shared.recordSuccessfulAccess(request: request)

        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteCredentials(at offsets: IndexSet) {
        // 🔥 FIXED: Implement real credential deletion
        Task {
            for index in offsets {
                let credential = credentials[index]
                do {
                    try await vaultManager.deleteCredential(id: credential.id)
                    print("✅ Deleted credential: \(credential.domain)")
                } catch {
                    errorMessage = "Failed to delete \(credential.domain): \(error.localizedDescription)"
                    print("❌ Delete error: \(error)")
                }
            }

            // Remove from local array
            credentials.remove(atOffsets: offsets)
        }
    }

    /// 🔥 NEW: Update existing credential
    func updateCredential(
        id: UUID,
        newPassword: String?,
        newUsername: String?,
        newNotes: String?
    ) async {
        do {
            try await vaultManager.updateCredential(
                id: id,
                newPassword: newPassword,
                newUsername: newUsername,
                newNotes: newNotes
            )
            await loadCredentials()  // Refresh list
            print("✅ Updated credential: \(id)")
        } catch {
            errorMessage = "Failed to update credential: \(error.localizedDescription)"
            print("❌ Update error: \(error)")
        }
    }

    /// Handle successful PIN unlock
    func onPINUnlockSuccess() async {
        await MainActor.run {
            updateLockState()
            print("🔓 UI: Unlocked with PIN - isUnlocked = \(isUnlocked)")
        }
        await loadCredentials()
    }

    private func updateLockState() {
        let newState = vaultManager.isUnlocked
        print("🔄 updateLockState: \(isUnlocked) → \(newState)")
        isUnlocked = newState
    }

    private func loadCredentials() async {
        // 🔥 FIXED: Load real credentials from vault
        guard isUnlocked else {
            credentials = []
            return
        }

        do {
            let loadedCredentials = try await vaultManager.listAllCredentials()
            credentials = loadedCredentials
            print("✅ UI: Loaded \(credentials.count) credentials")
        } catch {
            errorMessage = "Failed to load credentials: \(error.localizedDescription)"
            credentials = []
            print("❌ Load error: \(error)")
        }
    }
}
