import SwiftUI
import UniformTypeIdentifiers

/// Presented once after authentication. Confirmed skip is final; Settings exposes export only.
struct SereinBackupRestoreOnboarding: View {
    @ObservedObject var api: SereinAPI
    let onFinished: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var showPicker = false
    @State private var confirmSkip = false
    @State private var phase = "intro"
    @State private var status = ""
    @State private var legacyPassword = ""
    @State private var fileBytes: Data?
    @State private var backupInfo: SereinBackupStore.Info?
    @State private var snapshot: [String: Any]?
    @State private var mediaIncluded = false
    @State private var mergeCount = 0
    @State private var busy = false

    @MainActor private var currentUser: SereinUser? { api.user }
    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 16) {
                if phase == "intro" {
                    Image(systemName: "lock.doc").font(.system(size: 34)).foregroundStyle(SereinPalette.green)
                    Text("Restore chat history?").font(.system(size: 23, weight: .bold, relativeTo: .body))
                    Text("Choose an encrypted .srbk file to merge its messages into this account. Existing messages are never overwritten. Backups contain attachment references, not media bytes, so some media may be unavailable.").font(.system(size: 13, relativeTo: .body)).foregroundStyle(.secondary)
                    Button("Choose backup file") { showPicker = true }.buttonStyle(.borderedProminent).disabled(busy)
                    Button("Skip restore") { confirmSkip = true }.buttonStyle(.bordered).disabled(busy)
                } else if phase == "password" {
                    Text("Legacy backup password").font(.system(size: 22, weight: .bold, relativeTo: .body))
                    Text("This v1 file requires its original password. New v3 backups use a random server-held backup-only key requested through a one-use encrypted exchange; the service can access that key. Older v2 files remain restorable.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary)
                    SecureField("Original backup password", text: $legacyPassword).textContentType(.password).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button(busy ? "Opening…" : "Open legacy backup") { openSelectedBackup(password: legacyPassword) }.buttonStyle(.borderedProminent).disabled(busy || legacyPassword.isEmpty)
                    Button("Choose a different file") { showPicker = true }.disabled(busy)
                } else if phase == "confirm", let info = backupInfo, let data = snapshot {
                    Text("Review backup").font(.system(size: 22, weight: .bold, relativeTo: .body))
                    Text("Created \(info.createdAt)").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary)
                    Text("\((data["messages"] as? [[String: Any]] ?? []).count) message records will be merged. Existing message IDs are preserved.").font(.system(size: 13, relativeTo: .body))
                    Text(mediaIncluded ? "This iOS build does not import packaged media bytes yet. Attachment references remain, and some media may be unavailable." : "Media bytes are not included. Attachment references will remain, but missing or expired media will be unavailable.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary)
                    Button(busy ? "Merging…" : "Merge messages") { mergeSelectedBackup() }.buttonStyle(.borderedProminent).disabled(busy)
                    Button("Cancel restore") { clearSelection(); phase = "intro" }.disabled(busy)
                } else if phase == "complete" {
                    Image(systemName: "checkmark.circle.fill").font(.system(size: 36)).foregroundStyle(SereinPalette.green)
                    Text("Restore complete").font(.system(size: 22, weight: .bold, relativeTo: .body))
                    Text("\(mergeCount) new messages were merged. Existing records were kept. \(mediaIncluded ? "This iOS build does not restore packaged media bytes yet; some attachments may be unavailable." : "Attachment media may be unavailable because the backup contains references only.")").font(.system(size: 13, relativeTo: .body)).foregroundStyle(.secondary)
                    Button("Continue") { onFinished(); dismiss() }.buttonStyle(.borderedProminent)
                }
                if !status.isEmpty { Text(status).font(.system(size: 12, relativeTo: .body)).foregroundColor(status.lowercased().contains("could not") || status.lowercased().contains("failed") ? .red : .secondary) }
                Spacer(minLength: 0)
            }
            .padding(22)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .navigationTitle("Backup restore")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { if phase == "intro" { ToolbarItem(placement: .cancellationAction) { Button("Not now") { confirmSkip = true } } } }
        }
        .interactiveDismissDisabled()
        .fileImporter(isPresented: $showPicker, allowedContentTypes: [UTType(filenameExtension: "srbk", conformingTo: .data) ?? .data], allowsMultipleSelection: false) { result in
            switch result {
            case .failure: status = "File selection was cancelled. You can choose a backup or make the one-time skip decision."
            case .success(let urls): guard let url = urls.first else { status = "No backup file was selected."; return }; readSelectedBackup(url)
            }
        }
        .confirmationDialog("Skip restore permanently?", isPresented: $confirmSkip, titleVisibility: .visible) {
            Button("Skip permanently", role: .destructive) { onFinished(); dismiss() }
            Button("Go back", role: .cancel) { }
        } message: { Text("This is the one-time setup choice. If you confirm, Serein will not offer restore later in Settings. You can still export backups from Settings.") }
    }

    @MainActor private func readSelectedBackup(_ url: URL) {
        guard url.pathExtension.lowercased() == "srbk" else { status = "Only .srbk Serein backup files can be restored."; phase = "intro"; return }
        guard currentUser != nil else { status = "Sign in again before restoring a backup."; return }
        let hasScope = url.startAccessingSecurityScopedResource()
        defer { if hasScope { url.stopAccessingSecurityScopedResource() } }
        do {
            let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey])
            guard (resourceValues.fileSize ?? 0) <= SereinBackupStore.maximumBytes else { throw SereinBackupStore.BackupError.tooLarge }
            let bytes = try Data(contentsOf: url, options: [.mappedIfSafe])
            let info = try SereinBackupStore.inspect(bytes)
            fileBytes = bytes; backupInfo = info; status = ""
            if info.version == 1 { phase = "password" }
            else { phase = "opening"; openSelectedBackup(password: "") }
        } catch { status = error.localizedDescription }
    }

    @MainActor private func openSelectedBackup(password: String) {
        guard let user = currentUser, let bytes = fileBytes else { status = "Choose a backup file first."; return }
        busy = true; status = backupInfo?.version == 3 ? "Requesting the account backup key through a one-use encrypted exchange…" : "Authenticating and checking the encrypted snapshot…"
        Task {
            var keyBytes = Data()
            defer { if !keyBytes.isEmpty { keyBytes.resetBytes(in: 0..<keyBytes.count) } }
            do {
                if backupInfo?.version == 3 { keyBytes = try await api.requestBackupKey(accountID: user.id) }
                let keyForCodec = keyBytes
                let opened = try await Task.detached(priority: .userInitiated) {
                    try SereinBackupStore.open(accountID: user.id, username: user.username, legacyPassword: password, backupKey: keyForCodec, file: bytes)
                }.value
                guard let rows = opened.data["messages"] as? [[String: Any]], rows.count <= SereinBackupStore.maximumMessages,
                      (opened.data["snapshot_version"] as? Int) == 1 else { throw SereinBackupStore.BackupError.accountOrContentsInvalid }
                let includesMedia = ((opened.data["media"] as? [String: Any])?["included"] as? Bool) ?? false
                snapshot = opened.data; backupInfo = opened.info; mediaIncluded = includesMedia
                legacyPassword = ""; status = ""; phase = "confirm"; busy = false
            } catch {
                legacyPassword = ""; status = error.localizedDescription; busy = false
                if backupInfo?.version == 1 { phase = "password" } else { phase = "intro" }
            }
        }
    }

    @MainActor private func mergeSelectedBackup() {
        guard let user = currentUser, let messages = snapshot?["messages"] as? [[String: Any]] else { status = "Backup contents are unavailable."; return }
        busy = true; status = "Merging messages without replacing existing records…"
        do {
            let local = try SereinLocalStore(accountID: user.id)
            mergeCount = try local.mergeBackupMessages(messages)
            status = ""; phase = "complete"; busy = false; clearSelection(keepSnapshot: true)
        } catch { status = "Restore failed without replacing existing records: \(error.localizedDescription)"; busy = false }
    }

    private func clearSelection(keepSnapshot: Bool = false) {
        legacyPassword = ""; fileBytes = nil
        if !keepSnapshot { backupInfo = nil; snapshot = nil }
    }
}
