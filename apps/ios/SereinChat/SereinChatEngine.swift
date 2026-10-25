import CryptoKit
import Foundation
import Combine

struct SereinEncryptedAttachment: Codable, Hashable, Identifiable {
    var id: String { transferID }
    let transferID: String
    let filename: String
    let contentType: String
    let size: Int64

    var json: [String: Any] { ["transfer_id": transferID, "filename": filename, "content_type": contentType, "size": size] }
    init(transferID: String, filename: String, contentType: String, size: Int64) {
        self.transferID = transferID; self.filename = filename; self.contentType = contentType; self.size = size
    }
    init?(json: [String: Any]) {
        guard let id = json["transfer_id"] as? String,
              UUID(uuidString: id) != nil,
              let name = json["filename"] as? String, name.utf8.count <= 1024,
              let type = json["content_type"] as? String, type.utf8.count <= 128,
              let number = json["size"] as? NSNumber, number.int64Value >= 0,
              number.int64Value <= 64 * 1024 * 1024 else { return nil }
        self.transferID = id.lowercased(); self.filename = Self.safeFilename(name); self.contentType = type
        self.size = number.int64Value
    }
    private static func safeFilename(_ value: String) -> String {
        let scalars = value.unicodeScalars.prefix(150).map { scalar -> Unicode.Scalar in
            scalar == "/" || scalar == "\\" || CharacterSet.controlCharacters.contains(scalar) ? "_" : scalar
        }
        var result = String(String.UnicodeScalarView(scalars)).trimmingCharacters(in: .whitespacesAndNewlines)
        while result.hasPrefix(".") { result.removeFirst() }
        return result.isEmpty ? "attachment" : result
    }
}

struct SereinChatMessage: Identifiable {
    let id: String
    let conversationID: String
    let createdAt: String
    let text: String
    let mine: Bool
    let sender: String
    let status: String
    let attachment: SereinEncryptedAttachment?
}

struct SereinPeerKey: Identifiable {
    let id: String
    let name: String
    let fingerprint: String
    let previousFingerprint: String
    let trusted: Bool
    let key: SymmetricKey
    let layer2Key: SymmetricKey
}

@MainActor
final class SereinChatEngine: ObservableObject {
    @Published private(set) var messages: [SereinChatMessage] = []
    @Published private(set) var peerKeys: [SereinPeerKey] = []
    @Published private(set) var status = "Preparing protected device keys…"
    @Published private(set) var ready = false
    @Published private(set) var busy = false
    @Published private(set) var activeDevices: [SereinDevice] = []
    @Published private(set) var archived = false
    @Published private(set) var deletedAt: String?
    @Published private(set) var peerDisplayName: String

    private let api: SereinAPI
    private let contact: SereinContact
    private var crypto: SereinDeviceCrypto?
    private var layer2Crypto: SereinDeviceCrypto?
    private var local: SereinLocalStore?
    private var cursorTime: String?
    private var cursorID: String?
    private var pollRunning = false
    private var notificationsArmed = false
    private let chunkCipherBytes = 256 * 1024
    private let chunkClearBytes = 256 * 1024 - 16
    private let maxChunks = 512
    private let maxCipherBytes: Int64 = 64 * 1024 * 1024
    private let maxClearBytes: Int64 = 64 * 1024 * 1024

    init(api: SereinAPI, contact: SereinContact) { self.api = api; self.contact = contact; self.activeDevices = contact.devices; self.peerDisplayName = contact.display_name; self.archived = contact.isDeleted; self.deletedAt = contact.deleted_at }

    func initialize() async {
        guard let user = api.user, let device = api.currentDevice else { status = "Sign in again to use encrypted chat."; return }
        do {
            SereinAttachmentStore.shared.cleanTemporaryFiles()
            let deviceCrypto = try SereinDeviceCrypto.loadOrCreate(userID: user.id, deviceID: device.id)
            let deviceLayer2Crypto = try SereinDeviceCrypto.loadOrCreateLayer2(userID: user.id, deviceID: device.id)
            let localStore = try SereinLocalStore(accountID: user.id)
            crypto = deviceCrypto; layer2Crypto = deviceLayer2Crypto; local = localStore
            if contact.isDeleted { loadMessages(); ready = true; status = "Archived conversation · this account was deleted · read-only"; return }
            let registration = try await api.registerDeviceKey(deviceCrypto.publicJWK(), layer2PublicJWK: deviceLayer2Crypto.publicJWK())
            guard let ownFingerprint = try? SereinDeviceCrypto.fingerprintBundle(layer1: deviceCrypto.publicJWK(), layer2: deviceLayer2Crypto.publicJWK()), registration["fingerprint"] as? String == ownFingerprint else {
                throw SereinDeviceCrypto.CryptoError.invalidPublicKey
            }
            try await refreshPeerKeys()
            loadMessages()
            ready = true; status = peerStatus
            await retryPending()
            await poll()
            notificationsArmed = true
        } catch { status = error.localizedDescription }
    }

    var peerStatus: String {
        if activeDevices.isEmpty { return "No active recipient devices are available." }
        if peerKeys.count < activeDevices.count { return "\(activeDevices.count - peerKeys.count) active device(s) have not published a key." }
        let trusted = peerKeys.filter(\.trusted).count
        return trusted == activeDevices.count ? "All \(trusted) recipient-device fingerprints are verified on this iPhone." : "Verify \(activeDevices.count - trusted) device fingerprint(s) before sending."
    }

    func refreshPeerKeys() async throws {
        guard let user = api.user, let device = api.currentDevice, let crypto, let layer2Crypto else { throw ChatError.deviceUnavailable }
        let contactsData = try await api.contactsData()
        guard let rows = try JSONSerialization.jsonObject(with: contactsData) as? [[String: Any]],
              let latest = rows.first(where: { $0["user_id"] as? String == contact.user_id }) else { throw ChatError.contactUnavailable }
        peerDisplayName = latest["display_name"] as? String ?? peerDisplayName
        if latest["deleted"] as? Bool == true {
            archived = true; deletedAt = latest["deleted_at"] as? String; activeDevices = []; peerKeys = []
            status = "Archived conversation · this account was deleted · read-only"; loadMessages(); return
        }
        let latestDevices = (latest["devices"] as? [[String: Any]] ?? []).compactMap { row -> SereinDevice? in
            guard let id = row["id"] as? String else { return nil }
            return SereinDevice(id: id, name: row["name"] as? String ?? "Device", created_at: nil, last_seen_at: nil, current: nil, online: nil)
        }
        let directory = try await api.contactDeviceKeys(contact.user_id)
        guard directory["user_id"] as? String == contact.user_id, directory["username"] as? String == contact.username else { throw ChatError.keyDirectoryMismatch }
        let entries = directory["devices"] as? [[String: Any]] ?? []
        let activeIDs = Set(latestDevices.map(\.id))
        guard entries.allSatisfy({ entry in guard let id = entry["device_id"] as? String else { return false }; return activeIDs.contains(id) }) else { throw ChatError.deviceListChanged }
        var next: [SereinPeerKey] = []
        for target in latestDevices {
            guard let entry = entries.first(where: { $0["device_id"] as? String == target.id }),
                  entry["algorithm"] as? String == "ECDH-P256",
                  entry["key_version"] as? Int == 2,
                  let jwk = entry["public_key"] as? [String: Any],
                  let layer2JWK = entry["layer2_public_key"] as? [String: Any],
                  let serverFingerprint = entry["fingerprint"] as? String else { continue }
            let fingerprint = try SereinDeviceCrypto.fingerprintBundle(layer1: jwk, layer2: layer2JWK)
            guard fingerprint == serverFingerprint else { throw ChatError.keyDirectoryMismatch }
            let key = try crypto.conversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: contact.user_id, peerDeviceID: target.id, peerJWK: jwk)
            let layer2Key = try layer2Crypto.layer2ConversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: contact.user_id, peerDeviceID: target.id, peerJWK: layer2JWK)
            let old = local?.previousFingerprint(userID: contact.user_id, deviceID: target.id) ?? ""
            next.append(SereinPeerKey(id: target.id, name: target.name, fingerprint: fingerprint, previousFingerprint: old, trusted: old == fingerprint, key: key, layer2Key: layer2Key))
        }
        activeDevices = latestDevices
        peerKeys = next
        status = peerStatus
    }

    func trust(_ peer: SereinPeerKey) throws {
        guard peerKeys.contains(where: { $0.id == peer.id && $0.fingerprint == peer.fingerprint }),
              let local else { throw ChatError.deviceListChanged }
        try local.trust(userID: contact.user_id, deviceID: peer.id, fingerprint: peer.fingerprint)
        peerKeys = peerKeys.map { value in
            SereinPeerKey(id: value.id, name: value.name, fingerprint: value.fingerprint, previousFingerprint: value.fingerprint, trusted: value.id == peer.id || value.trusted, key: value.key, layer2Key: value.layer2Key)
        }
        status = peerStatus
    }

    func sendText(_ input: String) async {
        guard !contact.isDeleted && !archived else { status = "This archived conversation is read-only."; return }
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        guard text.unicodeScalars.count <= 4000 else { status = "Messages are limited to 4,000 characters."; return }
        do { try await sendMessage(text, attachment: nil) }
        catch { status = error.localizedDescription }
    }

    private func sendMessage(_ text: String, attachment: SereinEncryptedAttachment?) async throws {
        guard ready, let user = api.user, let device = api.currentDevice, let crypto, let local else { throw ChatError.deviceUnavailable }
        let targets = try trustedTargets()
        let messageID = UUID().uuidString.lowercased(), createdAt = Self.timestamp()
        var envelopes: [[String: String]] = []
        for peer in targets {
            var content: [String: Any] = ["version": 1, "text": text, "conversation_id": contact.user_id,
                "sender_user_id": user.id, "sender_device_id": device.id, "recipient_user_id": contact.user_id,
                "recipient_device_id": peer.id]
            if let attachment { content["attachment"] = attachment.json }
            envelopes.append(try crypto.encryptLayeredMessage(content, layer1Key: peer.key, layer2Key: peer.layer2Key, conversationID: contact.user_id, messageID: messageID,
                senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: peer.id)
                .merging(["to": peer.id, "crypto_version": "2"]) { _, new in new })
        }
        var row: [String: Any] = ["id": messageID, "conversation_id": contact.user_id, "created_at": createdAt,
            "text": text, "mine": true, "sender": user.display_name, "status": "pending", "envelopes": envelopes]
        if let attachment { row["attachment"] = attachment.json }
        try local.save(row); loadMessages()
        for envelope in envelopes {
            try await api.sendEncryptedEnvelope(id: messageID, to: envelope["to"] ?? "", iv: envelope["iv"] ?? "", ciphertext: envelope["ciphertext"] ?? "", cryptoVersion: Int(envelope["crypto_version"] ?? "1") ?? 1)
        }
        row["status"] = "accepted"; row.removeValue(forKey: "envelopes"); try local.save(row); loadMessages()
        status = "Encrypted message accepted by all recipient devices."
    }

    private func trustedTargets() throws -> [SereinPeerKey] {
        guard !activeDevices.isEmpty else { throw ChatError.noRecipientDevices }
        var result: [SereinPeerKey] = []
        for device in activeDevices {
            guard let peer = peerKeys.first(where: { $0.id == device.id }), peer.trusted else { throw ChatError.fingerprintRequired }
            result.append(peer)
        }
        return result
    }

    private func retryPending() async {
        guard !archived, let local else { return }
        for var row in local.messages(for: contact.user_id) where row["mine"] as? Bool == true && row["status"] as? String == "pending" {
            guard let id = row["id"] as? String, let envelopes = row["envelopes"] as? [[String: String]] else { continue }
            do {
                for envelope in envelopes { try await api.sendEncryptedEnvelope(id: id, to: envelope["to"] ?? "", iv: envelope["iv"] ?? "", ciphertext: envelope["ciphertext"] ?? "", cryptoVersion: Int(envelope["crypto_version"] ?? "1") ?? 1) }
                row["status"] = "accepted"; row.removeValue(forKey: "envelopes"); try local.save(row)
            } catch { status = "A queued encrypted message will retry when the server is reachable." }
        }
        loadMessages()
    }

    func poll() async {
        guard ready, !archived, !pollRunning, let user = api.user, let device = api.currentDevice, let crypto, let local else { return }
        pollRunning = true; defer { pollRunning = false }
        do {
            for _ in 0..<40 {
                let data = try await api.messageHistory(afterCreatedAt: cursorTime, afterID: cursorID)
                guard let page = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let items = page["items"] as? [[String: Any]], !items.isEmpty else { break }
                var stopped = false
                for item in items {
                    guard let id = item["id"] as? String, let created = item["created_at"] as? String,
                          let packet = item["payload"] as? [String: Any], packet["type"] as? String == "message" else { continue }
                    let senderDeviceID = packet["from"] as? String ?? ""
                    guard activeDevices.contains(where: { $0.id == senderDeviceID }) else { cursorTime = created; cursorID = id; continue }
                    if local.contains(messageID: id) { try? await api.acknowledgeMessage(id); cursorTime = created; cursorID = id; continue }
                    guard let peer = peerKeys.first(where: { $0.id == senderDeviceID }), peer.trusted else {
                        status = "A message is held. Verify the sender-device fingerprint before decrypting it."; stopped = true; break
                    }
                    do {
                        let clear = try crypto.decryptMessage(iv: packet["iv"] as? String ?? "", ciphertext: packet["ciphertext"] as? String ?? "", key: peer.key,
                            conversationID: contact.user_id, messageID: id, senderUserID: contact.user_id, senderDeviceID: senderDeviceID,
                            recipientUserID: user.id, recipientDeviceID: device.id)
                        guard clear["version"] as? Int == 1, clear["conversation_id"] as? String == contact.user_id,
                              clear["sender_user_id"] as? String == contact.user_id, clear["sender_device_id"] as? String == senderDeviceID,
                              clear["recipient_user_id"] as? String == user.id, clear["recipient_device_id"] as? String == device.id,
                              let text = clear["text"] as? String, !text.isEmpty, text.unicodeScalars.count <= 4000 else { throw ChatError.routeMismatch }
                        let attachment = (clear["attachment"] as? [String: Any]).flatMap(SereinEncryptedAttachment.init(json:))
                        if clear["attachment"] != nil && attachment == nil { throw ChatError.invalidAttachment }
                        var row: [String: Any] = ["id": id, "conversation_id": contact.user_id, "created_at": created, "text": text,
                            "mine": false, "sender": contact.display_name, "status": "received"]
                        if let attachment { row["attachment"] = attachment.json }
                        try local.save(row); try await api.acknowledgeMessage(id); if notificationsArmed { api.notifyIncomingMessage() }; cursorTime = created; cursorID = id
                    } catch {
                        status = error.localizedDescription; stopped = true; break
                    }
                }
                loadMessages()
                if stopped || page["has_more"] as? Bool != true { break }
            }
        } catch { status = "Secure message sync paused; it will retry." }
    }

    func sendFile(url: URL, filename: String, contentType: String) async {
        guard !contact.isDeleted && !archived else { status = "This archived conversation is read-only."; return }
        guard ready, let user = api.user, let device = api.currentDevice, let crypto else { status = "Protected device setup is not ready."; return }
        var contentKeyData: Data
        do { contentKeyData = try SereinDeviceCrypto.randomData(count: 32) } catch { status = error.localizedDescription; return }
        defer { contentKeyData.resetBytes(in: 0..<contentKeyData.count) }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let number = attributes[.size] as? NSNumber else { throw ChatError.fileUnavailable }
            let size = number.int64Value
            guard size >= 0, size <= maxClearBytes else { throw ChatError.fileTooLarge }
            let transferID = UUID().uuidString.lowercased()
            let count = max(1, Int((size + Int64(chunkClearBytes) - 1) / Int64(chunkClearBytes)))
            let cipherBytes = size + Int64(count) * 16
            guard count <= maxChunks, cipherBytes <= maxCipherBytes else { throw ChatError.fileTooLarge }
            let targets = try trustedTargets()
            let key = try SereinDeviceCrypto.key(from: contentKeyData)
            let prefix = try SereinDeviceCrypto.randomData(count: 4)
            let safeName = Self.safeFilename(filename)
            let safeType = contentType.isEmpty || contentType.utf8.count > 128 ? "application/octet-stream" : contentType
            let manifest: [String: Any] = ["version": 1, "transfer_id": transferID, "filename": safeName, "content_type": safeType,
                "size": size, "chunk_count": count, "content_key": contentKeyData.base64EncodedString(), "nonce_prefix": prefix.base64EncodedString()]
            var deviceEnvelopes: [[String: String]] = []
            let ownJWK = crypto.publicJWK()
            let ownKey = try crypto.conversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: user.id, peerDeviceID: device.id, peerJWK: ownJWK)
            let ownWrapped = try crypto.encryptManifest(manifest, key: ownKey, transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: device.id)
            deviceEnvelopes.append(["device_id": device.id, "iv": ownWrapped["iv"] ?? "", "ciphertext": ownWrapped["ciphertext"] ?? ""])
            for peer in targets {
                let wrapped = try crypto.encryptManifest(manifest, key: peer.key, transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: peer.id)
                deviceEnvelopes.append(["device_id": peer.id, "iv": wrapped["iv"] ?? "", "ciphertext": wrapped["ciphertext"] ?? ""])
            }
            try await api.createTransfer(["id": transferID, "recipient_user_id": contact.user_id, "chunk_count": count,
                                          "total_ciphertext_bytes": cipherBytes, "device_envelopes": deviceEnvelopes])
            var completed = false
            do {
                let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
                for index in 0..<count {
                    let wanted = min(chunkClearBytes, max(0, Int(size) - index * chunkClearBytes))
                    let clear = try handle.read(upToCount: wanted) ?? Data()
                    guard clear.count == wanted else { throw ChatError.fileChanged }
                    let encrypted = try SereinDeviceCrypto.encryptChunk(clear, key: key, noncePrefix: prefix, index: index, count: count,
                        transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id)
                    try await api.uploadTransferChunk(transferID, index: index, ciphertext: encrypted, digest: SereinDeviceCrypto.sha256Hex(encrypted))
                }
                guard (try handle.read(upToCount: 1) ?? Data()).isEmpty else { throw ChatError.fileChanged }
                completed = true
                let attachment = SereinEncryptedAttachment(transferID: transferID, filename: safeName, contentType: safeType, size: size)
                try await sendMessage("📎 \(safeName)", attachment: attachment)
            } catch {
                if !completed { try? await api.abortTransfer(transferID) }
                throw error
            }
        } catch { status = error.localizedDescription }
    }

    func localFile(for attachment: SereinEncryptedAttachment) -> URL? { SereinAttachmentStore.shared.existing(accountID: api.user?.id ?? "", transferID: attachment.transferID, filename: attachment.filename, expectedBytes: attachment.size) }

    func download(_ attachment: SereinEncryptedAttachment) async -> URL? {
        guard let user = api.user, let device = api.currentDevice, let crypto else { status = "Protected device setup is not ready."; return nil }
        if let existing = localFile(for: attachment) { return existing }
        var fileKeyData: Data?
        var temporary: URL?
        defer { if let count = fileKeyData?.count { fileKeyData?.resetBytes(in: 0..<count) }; if let temporary { try? FileManager.default.removeItem(at: temporary) } }
        do {
            let listData = try await api.transfersData()
            guard let records = try JSONSerialization.jsonObject(with: listData) as? [[String: Any]],
                  let transfer = records.first(where: { $0["id"] as? String == attachment.transferID }),
                  let senderUser = transfer["sender_user_id"] as? String,
                  let senderDevice = transfer["sender_device_id"] as? String,
                  let recipientUser = transfer["recipient_user_id"] as? String,
                  transfer["ready_at"] is String else { throw ChatError.transferUnavailable }
            guard recipientUser == user.id || senderUser == user.id else { throw ChatError.routeMismatch }
            let key: SymmetricKey
            if senderUser == user.id {
                guard senderDevice == device.id else { throw ChatError.routeMismatch }
                key = try crypto.conversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: user.id, peerDeviceID: device.id, peerJWK: crypto.publicJWK())
            } else {
                guard senderUser == contact.user_id, let peer = peerKeys.first(where: { $0.id == senderDevice && $0.trusted }) else { throw ChatError.fingerprintRequired }
                key = peer.key
            }
            let manifest = try crypto.decryptManifest(iv: transfer["manifest_iv"] as? String ?? "", ciphertext: transfer["manifest_ciphertext"] as? String ?? "", key: key,
                transferID: attachment.transferID, senderUserID: senderUser, senderDeviceID: senderDevice, recipientUserID: recipientUser, recipientDeviceID: device.id)
            guard manifest["version"] as? Int == 1, manifest["transfer_id"] as? String == attachment.transferID,
                  (manifest["filename"] as? String) == attachment.filename, (manifest["content_type"] as? String) == attachment.contentType,
                  (manifest["size"] as? NSNumber)?.int64Value == attachment.size,
                  let countNumber = manifest["chunk_count"] as? NSNumber, countNumber.intValue > 0,
                  countNumber.intValue <= maxChunks, countNumber.intValue == max(1, Int((attachment.size + Int64(chunkClearBytes) - 1) / Int64(chunkClearBytes))), countNumber.intValue == (transfer["chunk_count"] as? NSNumber)?.intValue,
                  let keyString = manifest["content_key"] as? String, let rawKey = Data(base64Encoded: keyString), rawKey.count == 32,
                  let prefixString = manifest["nonce_prefix"] as? String, let prefix = Data(base64Encoded: prefixString), prefix.count == 4 else { throw ChatError.manifestMismatch }
            guard (transfer["total_ciphertext_bytes"] as? NSNumber)?.int64Value == attachment.size + Int64(countNumber.intValue) * 16 else { throw ChatError.manifestMismatch }
            fileKeyData = rawKey
            let fileKey = try SereinDeviceCrypto.key(from: rawKey)
            temporary = FileManager.default.temporaryDirectory.appendingPathComponent("serein-clear-\(UUID().uuidString).part")
            FileManager.default.createFile(atPath: temporary!.path, contents: nil, attributes: [.protectionKey: FileProtectionType.complete])
            let output = try FileHandle(forWritingTo: temporary!)
            defer { try? output.close() }
            var total: Int64 = 0
            for index in 0..<countNumber.intValue {
                let (ciphertext, expectedHash) = try await api.downloadTransferChunk(attachment.transferID, index: index)
                guard SereinDeviceCrypto.sha256Hex(ciphertext) == expectedHash else { throw ChatError.chunkChecksum }
                let clear = try SereinDeviceCrypto.decryptChunk(ciphertext, key: fileKey, noncePrefix: prefix, index: index, count: countNumber.intValue,
                    transferID: attachment.transferID, senderUserID: senderUser, senderDeviceID: senderDevice, recipientUserID: recipientUser)
                total += Int64(clear.count); guard total <= attachment.size else { throw ChatError.manifestMismatch }
                try output.write(contentsOf: clear)
            }
            try output.synchronize()
            guard total == attachment.size else { throw ChatError.manifestMismatch }
            let saved = try SereinAttachmentStore.shared.save(accountID: user.id, transferID: attachment.transferID, filename: attachment.filename, from: temporary!, expectedBytes: attachment.size)
            try await api.acknowledgeTransfer(attachment.transferID)
            status = "Download saved. Tap Open to hand it to a compatible app."
            return saved
        } catch { status = error.localizedDescription; return nil }
    }

    private func loadMessages() {
        guard let local else { return }
        messages = local.messages(for: contact.user_id).compactMap { row in
            guard let id = row["id"] as? String, let conversation = row["conversation_id"] as? String,
                  let created = row["created_at"] as? String, let text = row["text"] as? String else { return nil }
            let attachment = (row["attachment"] as? [String: Any]).flatMap(SereinEncryptedAttachment.init(json:))
            return SereinChatMessage(id: id, conversationID: conversation, createdAt: created, text: text,
                mine: row["mine"] as? Bool ?? false, sender: row["sender"] as? String ?? contact.display_name,
                status: row["status"] as? String ?? "received", attachment: attachment)
        }.sorted { $0.createdAt < $1.createdAt }
    }

    private var peerKeysByID: [String: SereinPeerKey] { Dictionary(uniqueKeysWithValues: peerKeys.map { ($0.id, $0) }) }
    private static func timestamp() -> String { ISO8601DateFormatter().string(from: Date()) }
    private static func safeFilename(_ input: String) -> String {
        let scalars = input.unicodeScalars.prefix(150).map { scalar -> Unicode.Scalar in
            scalar == "/" || scalar == "\\" || CharacterSet.controlCharacters.contains(scalar) ? "_" : scalar
        }
        var value = String(String.UnicodeScalarView(scalars)).trimmingCharacters(in: .whitespacesAndNewlines)
        while value.hasPrefix(".") { value.removeFirst() }
        return value.isEmpty ? "attachment" : value
    }

    enum ChatError: LocalizedError {
        case deviceUnavailable, contactUnavailable, keyDirectoryMismatch, deviceListChanged, noRecipientDevices
        case fingerprintRequired, fileUnavailable, fileTooLarge, fileChanged, transferUnavailable, routeMismatch
        case manifestMismatch, chunkChecksum, invalidAttachment
        var errorDescription: String? {
            switch self {
            case .deviceUnavailable: return "Protected device setup is not ready."
            case .contactUnavailable: return "This account is no longer an accepted contact."
            case .keyDirectoryMismatch: return "The authenticated device-key directory did not match this contact."
            case .deviceListChanged: return "The contact device list changed. Refresh Contacts and verify the current fingerprints."
            case .noRecipientDevices: return "No active recipient devices are available."
            case .fingerprintRequired: return "Compare and verify each current device fingerprint through a separate trusted channel."
            case .fileUnavailable: return "The selected file is unavailable."
            case .fileTooLarge: return "This file exceeds the encrypted-transfer size limit."
            case .fileChanged: return "The selected file changed while it was being encrypted."
            case .transferUnavailable: return "The encrypted transfer is incomplete, expired, or unavailable on this device."
            case .routeMismatch: return "Encrypted message routing did not match this account and device."
            case .manifestMismatch: return "The authenticated file manifest did not match the chat notice or size limits."
            case .chunkChecksum: return "Encrypted file data failed its transport checksum."
            case .invalidAttachment: return "Encrypted attachment details are malformed."
            }
        }
    }
}
