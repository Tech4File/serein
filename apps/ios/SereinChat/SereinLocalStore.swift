import CryptoKit
import Foundation

/// Account-scoped local history and peer-key trust, encrypted with a device-only Keychain key.
@MainActor
final class SereinLocalStore {
    private let accountID: String
    private let aad: Data
    private let fileURL: URL
    private let key: SymmetricKey
    private var root: [String: Any]

    init(accountID: String) throws {
        guard UUID(uuidString: accountID) != nil,
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw StoreError.storageUnavailable
        }
        self.accountID = accountID
        self.aad = Data("serein-local-history-v1:\(accountID)".utf8)
        let directory = support.appendingPathComponent("Serein", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.protectionKey: FileProtectionType.complete])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var directoryURL = directory
        try? directoryURL.setResourceValues(values)
        self.fileURL = directory.appendingPathComponent("history-\(accountID).bin")
        let keyAccount = "local-store-v1:\(accountID)"
        let localKey: SymmetricKey
        if let data = try SereinKeychain.read(account: keyAccount) {
            guard data.count == 32 else { throw StoreError.keyUnavailable }
            localKey = SymmetricKey(data: data)
        } else {
            let bytes = try SereinDeviceCrypto.randomData(count: 32)
            try SereinKeychain.write(bytes, account: keyAccount)
            localKey = SymmetricKey(data: bytes)
        }
        self.key = localKey
        if FileManager.default.fileExists(atPath: fileURL.path) {
            let fileValues = try fileURL.resourceValues(forKeys: [.fileSizeKey])
            guard (fileValues.fileSize ?? 0) <= SereinBackupStore.maximumBytes else { throw StoreError.historyUnavailable }
            let packed = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
            let sealed = try AES.GCM.SealedBox(combined: packed)
            let clear = try AES.GCM.open(sealed, using: localKey, authenticating: aad)
            guard let decoded = try JSONSerialization.jsonObject(with: clear) as? [String: Any],
                  decoded["version"] as? Int == 1, decoded["messages"] is [[String: Any]],
                  decoded["trust"] is [String: Any] else { throw StoreError.historyUnavailable }
            var migrated = decoded
            if migrated["ratchets"] == nil { migrated["ratchets"] = [String: String]() }
            else if !(migrated["ratchets"] is [String: String]) { throw StoreError.historyUnavailable }
            self.root = migrated
        } else { self.root = ["version": 1, "messages": [[String: Any]](), "trust": [String: Any](), "ratchets": [String: String]() }
    }

    static func delete(accountID: String) throws {
        guard UUID(uuidString: accountID) != nil,
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { throw StoreError.storageUnavailable }
        let file = support.appendingPathComponent("Serein", isDirectory: true).appendingPathComponent("history-\(accountID).bin")
        if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
        try SereinKeychain.delete(account: "local-store-v1:\(accountID)")
    }
    func messages(for conversationID: String) -> [[String: Any]] {
        (root["messages"] as? [[String: Any]] ?? []).filter { $0["conversation_id"] as? String == conversationID }
    }
    func contains(messageID: String) -> Bool {
        (root["messages"] as? [[String: Any]] ?? []).contains { $0["id"] as? String == messageID }
    }
    func previousFingerprint(userID: String, deviceID: String) -> String {
        let value = (root["trust"] as? [String: Any] ?? [:])["\(userID):\(deviceID)"]
        return (value as? String) ?? (value as? [String: Any])?["fingerprint"] as? String ?? ""
    }
    func previousRatchetVersion(userID: String, deviceID: String) -> Int {
        let value = (root["trust"] as? [String: Any] ?? [:])["\(userID):\(deviceID)"]
        return (value as? [String: Any])?["ratchet_version"] as? Int ?? 2
    }
    func trust(userID: String, deviceID: String, fingerprint: String, ratchetVersion: Int) throws {
        guard ratchetVersion == 2 || ratchetVersion == 3 else { throw StoreError.invalidMessage }
        var values = root["trust"] as? [String: Any] ?? [:]
        values["\(userID):\(deviceID)"] = ["fingerprint": fingerprint, "ratchet_version": ratchetVersion]
        let previous = root; root["trust"] = values
        do { try flush() } catch { root = previous; throw error }
    }
    func ratchetSnapshot(_ name: String) throws -> Data? {
        guard !name.isEmpty, name.utf8.count <= 512 else { throw StoreError.invalidMessage }
        guard let encoded = (root["ratchets"] as? [String: String] ?? [:])[name] else { return nil }
        guard let data = Data(base64Encoded: encoded), !data.isEmpty, data.count <= 1_048_576 else { throw StoreError.historyUnavailable }
        return data
    }
    func save(_ message: [String: Any]) throws { try save(message, ratchetSnapshots: [:]) }
    func save(_ message: [String: Any], ratchetSnapshots: [String: Data]) throws {
        guard let id = message["id"] as? String, ratchetSnapshots.count <= 64 else { throw StoreError.invalidMessage }
        let previous = root
        var messages = root["messages"] as? [[String: Any]] ?? []
        messages.removeAll { $0["id"] as? String == id }; messages.append(message)
        var ratchets = root["ratchets"] as? [String: String] ?? [:]
        for (name, snapshot) in ratchetSnapshots {
            guard !name.isEmpty, name.utf8.count <= 512, !snapshot.isEmpty, snapshot.count <= 1_048_576 else { throw StoreError.invalidMessage }
            ratchets[name] = snapshot.base64EncodedString()
        }
        root["messages"] = messages; root["ratchets"] = ratchets
        do { try flush() } catch { root = previous; throw error }
    }

    func backupMessages() -> [[String: Any]] {
        root["messages"] as? [[String: Any]] ?? []
    }

    @discardableResult
    func mergeBackupMessages(_ incoming: [[String: Any]]) throws -> Int {
        guard incoming.count <= SereinBackupStore.maximumMessages else { throw StoreError.historyUnavailable }
        var existing = root["messages"] as? [[String: Any]] ?? []
        var seen = Set<String>(), incomingIDs = Set<String>()
        for row in existing { if let id = row["id"] as? String { seen.insert(id) } }
        var added = 0
        for row in incoming {
            guard let id = row["id"] as? String, !id.isEmpty, id.utf8.count <= 128,
                  let conversation = row["conversation_id"] as? String, !conversation.isEmpty, conversation.utf8.count <= 128,
                  let created = row["created_at"] as? String, created.utf8.count <= 128, Self.validTimestamp(created),
                  let status = row["status"] as? String, ["pending", "accepted", "received"].contains(status),
                  incomingIDs.insert(id).inserted else { throw StoreError.invalidMessage }
            if seen.insert(id).inserted { existing.append(row); added += 1 }
        }
        existing.sort {
            let left = $0["created_at"] as? String ?? ""
            let right = $1["created_at"] as? String ?? ""
            if left != right { return left < right }
            return ($0["id"] as? String ?? "") < ($1["id"] as? String ?? "")
        }
        root["messages"] = existing
        try flush()
        return added
    }

    private static func validTimestamp(_ value: String) -> Bool {
        let formatter = ISO8601DateFormatter()
        if formatter.date(from: value) != nil { return true }
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) != nil
    }

    private func flush() throws {
        let clear = try JSONSerialization.data(withJSONObject: root)
        guard clear.count <= SereinBackupStore.maximumBytes else { throw StoreError.historyUnavailable }
        let sealed = try AES.GCM.seal(clear, using: key, authenticating: aad)
        guard let packed = sealed.combined else { throw StoreError.historyUnavailable }
        do {
            try packed.write(to: fileURL, options: [.atomic, .completeFileProtection])
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            var target = fileURL
            try? target.setResourceValues(values)
        } catch { throw StoreError.historyUnavailable }
    }

    enum StoreError: LocalizedError {
        case storageUnavailable, keyUnavailable, historyUnavailable, invalidMessage
        var errorDescription: String? {
            switch self {
            case .storageUnavailable: return "Protected local message storage is unavailable."
            case .keyUnavailable: return "The local message-history key is unavailable on this device."
            case .historyUnavailable: return "Encrypted local message history could not be opened or saved."
            case .invalidMessage: return "The local message record is malformed."
            }
        }
    }
}
