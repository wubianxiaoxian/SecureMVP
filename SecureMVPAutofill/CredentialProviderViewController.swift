//
//  CredentialProviderViewController.swift
//  SecureMVPAutofill
//
//  Updated to use VaultManager for real credential data
//

import UIKit
import AuthenticationServices

final class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: - Properties

    private var credentials: [Credential] = []
    private var filteredCredentials: [Credential] = []
    private let vaultManager = VaultManager.shared

    private lazy var tableView: UITableView = {
        let table = UITableView()
        table.register(CredentialTableViewCell.self, forCellReuseIdentifier: CredentialTableViewCell.identifier)
        table.dataSource = self
        table.delegate = self
        table.tableFooterView = UIView()
        table.translatesAutoresizingMaskIntoConstraints = false
        return table
    }()

    private lazy var searchBar: UISearchBar = {
        let searchBar = UISearchBar()
        searchBar.placeholder = "Search Passwords"
        searchBar.delegate = self
        searchBar.translatesAutoresizingMaskIntoConstraints = false
        return searchBar
    }()

    private lazy var navigationBar: UINavigationBar = {
        let navBar = UINavigationBar()
        let navItem = UINavigationItem(title: "Select a password to fill")
        navItem.rightBarButtonItem = UIBarButtonItem(
            title: "Cancel",
            style: .plain,
            target: self,
            action: #selector(dismissViewController)
        )
        navBar.setItems([navItem], animated: false)
        navBar.translatesAutoresizingMaskIntoConstraints = false
        return navBar
    }()

    private lazy var loadingIndicator: UIActivityIndicatorView = {
        let indicator = UIActivityIndicatorView(style: .large)
        indicator.translatesAutoresizingMaskIntoConstraints = false
        indicator.hidesWhenStopped = true
        return indicator
    }()

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        overrideUserInterfaceStyle = .light
        view.backgroundColor = .white
        layoutUI()
        loadCredentials()
    }

    // MARK: - UI Setup

    private func layoutUI() {
        view.addSubview(navigationBar)
        view.addSubview(searchBar)
        view.addSubview(tableView)
        view.addSubview(loadingIndicator)

        NSLayoutConstraint.activate([
            navigationBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            navigationBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            navigationBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            searchBar.topAnchor.constraint(equalTo: navigationBar.bottomAnchor),
            searchBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            searchBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            tableView.topAnchor.constraint(equalTo: searchBar.bottomAnchor, constant: 10),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            loadingIndicator.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            loadingIndicator.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }

    // MARK: - Data Loading

    private func loadCredentials() {
        loadingIndicator.startAnimating()
        tableView.isHidden = true

        Task {
            do {
                // Check if vault is initialized
                guard vaultManager.isVaultInitialized() else {
                    await showError("Vault not initialized. Please set up SecureMVP first.")
                    return
                }

                // Unlock vault if needed (this will trigger biometric auth)
                if !vaultManager.isUnlocked {
                    try await vaultManager.unlockVault()
                }

                // Load all credentials from vault
                let allCredentials = try await vaultManager.listAllCredentials()

                await MainActor.run {
                    self.credentials = allCredentials
                    self.filteredCredentials = allCredentials
                    self.tableView.reloadData()
                    self.loadingIndicator.stopAnimating()
                    self.tableView.isHidden = false

                    print("✅ Loaded \(allCredentials.count) credentials in Extension")
                }

            } catch {
                await showError("Failed to load credentials: \(error.localizedDescription)")
            }
        }
    }

    private func showError(_ message: String) async {
        await MainActor.run {
            loadingIndicator.stopAnimating()

            let alert = UIAlertController(
                title: "Error",
                message: message,
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
                self.extensionContext.cancelRequest(withError: NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.userCanceled.rawValue
                ))
            })
            present(alert, animated: true)
        }
    }

    // MARK: - Actions

    @objc private func dismissViewController() {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userCanceled.rawValue
        ))
    }
}

// MARK: - UITableViewDataSource

extension CredentialProviderViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return filteredCredentials.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(
            withIdentifier: CredentialTableViewCell.identifier,
            for: indexPath
        ) as! CredentialTableViewCell

        let credential = filteredCredentials[indexPath.row]
        cell.configure(with: credential)
        return cell
    }
}

// MARK: - UITableViewDelegate

extension CredentialProviderViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let selectedCredential = filteredCredentials[indexPath.row]

        // Create ASPasswordCredential with real data
        let passwordCredential = ASPasswordCredential(
            user: selectedCredential.username,
            password: selectedCredential.password
        )

        // Complete request with selected credential
        extensionContext.completeRequest(
            withSelectedCredential: passwordCredential,
            completionHandler: nil
        )
    }
}

// MARK: - UISearchBarDelegate

extension CredentialProviderViewController: UISearchBarDelegate {
    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) {
        if searchText.isEmpty {
            filteredCredentials = credentials
        } else {
            filteredCredentials = credentials.filter { credential in
                credential.domain.lowercased().contains(searchText.lowercased()) ||
                credential.username.lowercased().contains(searchText.lowercased())
            }
        }
        tableView.reloadData()
    }

    func searchBarSearchButtonClicked(_ searchBar: UISearchBar) {
        searchBar.resignFirstResponder()
    }
}
