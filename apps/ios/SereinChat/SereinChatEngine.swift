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
    let ratchetVersion: Int
    let previousRatchetVersion: Int
    let publicJWK: [String: Any]
    let layer2PublicJWK: [String: Any]
    let trusted: Bool
    let key: SymmetricKey
    let layer2Key: SymmetricKey
}

@MainActor
final class SereinChatEngine: ObservableObject {
    private static func canonicalConversationID(_ first: String, _ second: String) -> String { [first, second].sorted().joined(separator: ":") }
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
    private var ownFingerprint = ""
    private var cursorTime: String?
    private var cursorID: String?
    private var pollRunning = false
    private var notificationsArmed = false
    private let chunkCipherBytes = 256 * 1024
    private let chunkClearBytes = 256 * 1024 - 32
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
            ownFingerprint = try SereinDeviceCrypto.fingerprintBundle(layer1: deviceCrypto.publicJWK(), layer2: deviceLayer2Crypto.publicJWK())
            let ratchetVersion = SereinCoreBridge.version == "unavailable" ? 2 : 3
            let registration = try await api.registerDeviceKey(deviceCrypto.publicJWK(), layer2PublicJWK: deviceLayer2Crypto.publicJWK(), ratchetVersion: ratchetVersion)
            guard registration["fingerprint"] as? String == ownFingerprint else {
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
            let ratchetVersion = entry["ratchet_version"] as? Int ?? 2
            guard ratchetVersion == 2 || ratchetVersion == 3 else { throw ChatError.keyDirectoryMismatch }
            let old = local?.previousFingerprint(userID: contact.user_id, deviceID: target.id) ?? ""
            let oldVersion = local?.previousRatchetVersion(userID: contact.user_id, deviceID: target.id) ?? 2
            next.append(SereinPeerKey(id: target.id, name: target.name, fingerprint: fingerprint, previousFingerprint: old,
                ratchetVersion: ratchetVersion, previousRatchetVersion: oldVersion, publicJWK: jwk, layer2PublicJWK: layer2JWK,
                trusted: old == fingerprint && oldVersion == ratchetVersion, key: key, layer2Key: layer2Key))
        }
        activeDevices = latestDevices
        peerKeys = next
        status = peerStatus
    }

    func trust(_ peer: SereinPeerKey) throws {
        guard peerKeys.contains(where: { $0.id == peer.id && $0.fingerprint == peer.fingerprint }),
              let local else { throw ChatError.deviceListChanged }
        try local.trust(userID: contact.user_id, deviceID: peer.id, fingerprint: peer.fingerprint, ratchetVersion: peer.ratchetVersion)
        peerKeys = peerKeys.map { value in
            SereinPeerKey(id: value.id, name: value.name, fingerprint: value.fingerprint, previousFingerprint: value.fingerprint,
                ratchetVersion: value.ratchetVersion, previousRatchetVersion: value.ratchetVersion, publicJWK: value.publicJWK,
                layer2PublicJWK: value.layer2PublicJWK, trusted: value.id == peer.id || value.trusted, key: value.key, layer2Key: value.layer2Key)
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

    private func ratchetStateName(peer: SereinPeerKey, layer: String, user: SereinUser, device: SereinDevice) -> String {
        "live-ratchet-v1:\(layer):\(user.id):\(device.id):\(contact.user_id):\(peer.id):\(ownFingerprint):\(peer.fingerprint)"
    }

    private func ratchetSessionID(peer: SereinPeerKey, layer: String, user: SereinUser, device: SereinDevice) -> Data {
        let parties = ["\(user.id):\(device.id):\(ownFingerprint)", "\(contact.user_id):\(peer.id):\(peer.fingerprint)"].sorted()
        var result = Data(SHA256.hash(data: Data("Serein/\(layer)/live-ratchet-session/v1|\(parties.joined(separator: "|"))".utf8)).prefix(16)
        if result.allSatisfy({ $0 == 0 }) { result[result.count - 1] = 1 }
        return result
    }

    private func openLayeredRatchet(_ peer: SereinPeerKey, user: SereinUser, device: SereinDevice) throws -> SereinLayeredRatchet {
        guard let local, let crypto, let layer2Crypto else { throw ChatError.deviceUnavailable }
        let name1 = ratchetStateName(peer: peer, layer: "layer1", user: user, device: device)
        let name2 = ratchetStateName(peer: peer, layer: "layer2", user: user, device: device)
        let saved1 = try local.ratchetSnapshot(name1), saved2 = try local.ratchetSnapshot(name2)
        guard (saved1 == nil) == (saved2 == nil) else { throw SereinCoreBridge.RatchetError.operationFailed }
        if let saved1, let saved2 {
            let first = try SereinCoreBridge.Ratchet(snapshot: saved1)
            do { return SereinLayeredRatchet(layer1: first, layer2: try SereinCoreBridge.Ratchet(snapshot: saved2), layer1Name: name1, layer2Name: name2) }
            catch { first.close(); throw error }
        }
        var created: [SereinCoreBridge.Ratchet] = []
        do {
            let first = try createRatchet(peer: peer, layer: "layer1", user: user, device: device, crypto: crypto)
            created.append(first)
            let second = try createRatchet(peer: peer, layer: "layer2", user: user, device: device, crypto: layer2Crypto)
            created.append(second)
            return SereinLayeredRatchet(layer1: first, layer2: second, layer1Name: name1, layer2Name: name2)
        } catch { created.forEach { $0.close() }; throw error }
    }

    private func createRatchet(peer: SereinPeerKey, layer: String, user: SereinUser, device: SereinDevice, crypto: SereinDeviceCrypto) throws -> SereinCoreBridge.Ratchet {
        let jwk = layer == "layer1" ? peer.publicJWK : peer.layer2PublicJWK
        var bootstrap = try crypto.ratchetBootstrapSecret(localUserID: user.id, localDeviceID: device.id, peerUserID: contact.user_id, peerDeviceID: peer.id, peerJWK: jwk, purpose: layer)
        let sessionID = ratchetSessionID(peer: peer, layer: layer, user: user, device: device)
        defer { bootstrap.resetBytes(in: 0..<bootstrap.count) }
        let chains = try SereinCoreBridge.deriveChains(bootstrapSecret: bootstrap, sessionID: sessionID)
        let direction: UInt8 = "\(user.id):\(device.id)" < "\(contact.user_id):\(peer.id)" ? 0 : 1
        let send = direction == 0 ? chains.initiatorToResponder : chains.responderToInitiator
        let receive = direction == 0 ? chains.responderToInitiator : chains.initiatorToResponder
        return try SereinCoreBridge.Ratchet(sessionID: sessionID, sendDirection: direction, sendChainKey: send, receiveChainKey: receive)
    }

    private func sendMessage(_ text: String, attachment: SereinEncryptedAttachment?) async throws {
        guard ready, let user = api.user, let device = api.currentDevice, let crypto, let local else { throw ChatError.deviceUnavailable }
        let targets = try trustedTargets()
        let messageID = UUID().uuidString.lowercased(), createdAt = Self.timestamp()
        var envelopes: [[String: String]] = [], snapshots: [String: Data] = [], opened: [SereinLayeredRatchet] = []
        defer { opened.forEach { $0.close() }; snapshots.values.forEach { var value = $0; value.resetBytes(in: 0..<value.count) } }
        let conversationID = Self.canonicalConversationID(user.id, contact.user_id)
        for peer in targets {
            var content: [String: Any] = ["version": 1, "text": text, "conversation_id": conversationID,
                "sender_user_id": user.id, "sender_device_id": device.id, "recipient_user_id": contact.user_id,
                "recipient_device_id": peer.id]
            if let attachment { content["attachment"] = attachment.json }
            if peer.ratchetVersion >= 3 && SereinCoreBridge.version != "unavailable" {
                let session = try openLayeredRatchet(peer, user: user, device: device); opened.append(session)
                let route = ["conversationId": conversationID, "messageId": messageID, "senderUserId": user.id,
                    "senderDeviceId": device.id, "recipientUserId": contact.user_id, "recipientDeviceId": peer.id]
                let clear = try JSONSerialization.data(withJSONObject: content)
                var encrypted = try session.encrypt(clear, metadata: route)
                encrypted["to"] = peer.id; encrypted["crypto_version"] = "3"; envelopes.append(encrypted)
                for (name, snapshot) in try session.snapshots() { snapshots[name] = snapshot }
            } else {
                envelopes.append(try crypto.encryptLayeredMessage(content, layer1Key: peer.key, layer2Key: peer.layer2Key, conversationID: conversationID, messageID: messageID,
                    senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: peer.id)
                    .merging(["to": peer.id, "crypto_version": "2"]) { _, new in new })
            }
        }
        var row: [String: Any] = ["id": messageID, "conversation_id": contact.user_id, "created_at": createdAt,
            "text": text, "mine": true, "sender": user.display_name, "status": "pending", "envelopes": envelopes]
        if let attachment { row["attachment"] = attachment.json }
        if snapshots.isEmpty { try local.save(row) } else { try local.save(row, ratchetSnapshots: snapshots) }; loadMessages()
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

    private func incomingRow(_ clear: [String: Any], messageID: String, senderDeviceID: String, createdAt: String, user: SereinUser, device: SereinDevice) throws -> [String: Any] {
        let conversationID = Self.canonicalConversationID(user.id, contact.user_id)
        guard clear["version"] as? Int == 1,
              (clear["conversation_id"] as? String == conversationID || clear["conversation_id"] as? String == user.id),
              clear["sender_user_id"] as? String == contact.user_id, clear["sender_device_id"] as? String == senderDeviceID,
              clear["recipient_user_id"] as? String == user.id, clear["recipient_device_id"] as? String == device.id,
              let text = clear["text"] as? String, !text.isEmpty, text.unicodeScalars.count <= 4000 else { throw ChatError.routeMismatch }
        let attachment = (clear["attachment"] as? [String: Any]).flatMap(SereinEncryptedAttachment.init(json:))
        if clear["attachment"] != nil && attachment == nil { throw ChatError.invalidAttachment }
        var row: [String: Any] = ["id": messageID, "conversation_id": contact.user_id, "created_at": createdAt,
            "text": text, "mine": false, "sender": contact.display_name, "status": "received"]
        if let attachment { row["attachment"] = attachment.json }
        return row
    }

    private func decryptAndStoreIncoming(peer: SereinPeerKey, packet: [String: Any], messageID: String, senderDeviceID: String,
                                         createdAt: String, user: SereinUser, device: SereinDevice) throws {
        guard let crypto, let local else { throw ChatError.deviceUnavailable }
        let version = packet["crypto_version"] as? Int ?? 1
        guard (1...3).contains(version) else { throw ChatError.routeMismatch }
        let conversationID = Self.canonicalConversationID(user.id, contact.user_id)
        if version == 3 {
            guard peer.ratchetVersion >= 3 else { throw ChatError.routeMismatch }
            let session = try openLayeredRatchet(peer, user: user, device: device); defer { session.close() }
            let route = ["conversationId": conversationID, "messageId": messageID, "senderUserId": contact.user_id,
                "senderDeviceId": senderDeviceID, "recipientUserId": user.id, "recipientDeviceId": device.id]
            var clearData = try session.decrypt(iv: packet["iv"] as? String ?? "", ciphertext: packet["ciphertext"] as? String ?? "", metadata: route)
            defer { clearData.resetBytes(in: 0..<clearData.count) }
            guard let clear = try JSONSerialization.jsonObject(with: clearData) as? [String: Any] else { throw ChatError.routeMismatch }
            let row = try incomingRow(clear, messageID: messageID, senderDeviceID: senderDeviceID, createdAt: createdAt, user: user, device: device)
            try local.save(row, ratchetSnapshots: session.snapshots())
        } else {
            let clear: [String: Any]
            do { clear = try crypto.decryptLayeredMessage(iv: packet["iv"] as? String ?? "", ciphertext: packet["ciphertext"] as? String ?? "", layer1Key: peer.key, layer2Key: peer.layer2Key, cryptoVersion: version,
                conversationID: conversationID, messageID: messageID, senderUserID: contact.user_id, senderDeviceID: senderDeviceID,
                recipientUserID: user.id, recipientDeviceID: device.id) }
            catch { clear = try crypto.decryptLayeredMessage(iv: packet["iv"] as? String ?? "", ciphertext: packet["ciphertext"] as? String ?? "", layer1Key: peer.key, layer2Key: peer.layer2Key, cryptoVersion: version,
                conversationID: user.id, messageID: messageID, senderUserID: contact.user_id, senderDeviceID: senderDeviceID,
                recipientUserID: user.id, recipientDeviceID: device.id) }
            try local.save(incomingRow(clear, messageID: messageID, senderDeviceID: senderDeviceID, createdAt: createdAt, user: user, device: device))
        }
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
                    if local.contains(messageID: id) { try await api.acknowledgeMessage(id); cursorTime = created; cursorID = id; continue }
                    guard let peer = peerKeys.first(where: { $0.id == senderDeviceID }), peer.trusted else {
                        status = "A message is held. Verify the sender-device fingerprint before decrypting it."; stopped = true; break
                    }
                    do {
                        try decryptAndStoreIncoming(peer: peer, packet: packet, messageID: id, senderDeviceID: senderDeviceID, createdAt: created, user: user, device: device)
                        try await api.acknowledgeMessage(id); if notificationsArmed { api.notifyIncomingMessage() }; cursorTime = created; cursorID = id
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
        guard ready, let user = api.user, let device = api.currentDevice, let crypto, let layer2Crypto else { status = "Protected device setup is not ready."; return }
        var contentKeyData: Data
        var layer2ContentKeyData: Data
        do { contentKeyData = try SereinDeviceCrypto.randomData(count: 32); layer2ContentKeyData = try SereinDeviceCrypto.randomData(count: 32) } catch { status = error.localizedDescription; return }
        defer { contentKeyData.resetBytes(in: 0..<contentKeyData.count); layer2ContentKeyData.resetBytes(in: 0..<layer2ContentKeyData.count) }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let number = attributes[.size] as? NSNumber else { throw ChatError.fileUnavailable }
            let size = number.int64Value
            guard size >= 0, size <= maxClearBytes else { throw ChatError.fileTooLarge }
            let transferID = UUID().uuidString.lowercased()
            let count = max(1, Int((size + Int64(chunkClearBytes) - 1) / Int64(chunkClearBytes)))
            let cipherBytes = size + Int64(count) * 32
            guard count <= maxChunks, cipherBytes <= maxCipherBytes else { throw ChatError.fileTooLarge }
            let targets = try trustedTargets()
            let key = try SereinDeviceCrypto.key(from: contentKeyData)
            let layer2Key = try SereinDeviceCrypto.key(from: layer2ContentKeyData)
            var prefix = try SereinDeviceCrypto.randomData(count: 4)
            var layer2Prefix = try SereinDeviceCrypto.randomData(count: 4)
            defer { prefix.resetBytes(in: 0..<prefix.count); layer2Prefix.resetBytes(in: 0..<layer2Prefix.count) }
            let safeName = Self.safeFilename(filename)
            let safeType = contentType.isEmpty || contentType.utf8.count > 128 ? "application/octet-stream" : contentType
            let manifest: [String: Any] = ["version": 1, "chunk_crypto_version": 2, "transfer_id": transferID, "filename": safeName, "content_type": safeType,
                "size": size, "chunk_count": count, "content_key": contentKeyData.base64EncodedString(), "nonce_prefix": prefix.base64EncodedString(),
                "layer2_content_key": layer2ContentKeyData.base64EncodedString(), "layer2_nonce_prefix": layer2Prefix.base64EncodedString()]
            var deviceEnvelopes: [[String: Any]] = []
            let ownJWK = crypto.publicJWK()
            let ownKey = try crypto.conversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: user.id, peerDeviceID: device.id, peerJWK: ownJWK)
            let ownWrapped = try crypto.encryptManifest(manifest, key: ownKey, transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: device.id)
            let ownLayer2Key = try layer2Crypto.layer2ConversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: user.id, peerDeviceID: device.id, peerJWK: layer2Crypto.publicJWK())
            let ownOuter = try crypto.encryptManifestLayer2(ownWrapped, key: ownLayer2Key, transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: device.id)
            deviceEnvelopes.append(["device_id": device.id, "crypto_version": 2, "iv": ownOuter["iv"] ?? "", "ciphertext": ownOuter["ciphertext"] ?? ""])
            for peer in targets {
                let inner = try crypto.encryptManifest(manifest, key: peer.key, transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: peer.id)
                let wrapped = try crypto.encryptManifestLayer2(inner, key: peer.layer2Key, transferID: transferID, senderUserID: user.id, senderDeviceID: device.id, recipientUserID: contact.user_id, recipientDeviceID: peer.id)
                deviceEnvelopes.append(["device_id": peer.id, "crypto_version": 2, "iv": wrapped["iv"] ?? "", "ciphertext": wrapped["ciphertext"] ?? ""])
            }
            try await api.createTransfer(["id": transferID, "recipient_user_id": contact.user_id, "chunk_count": count, "chunk_crypto_version": 2,
                                          "total_ciphertext_bytes": cipherBytes, "device_envelopes": deviceEnvelopes])
            var completed = false
            do {
                let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
                for index in 0..<count {
                    let wanted = min(chunkClearBytes, max(0, Int(size) - index * chunkClearBytes))
                    var clear = try handle.read(upToCount: wanted) ?? Data()
                    defer { clear.resetBytes(in: 0..<clear.count) }
                    guard clear.count == wanted else { throw ChatError.fileChanged }
                    let encrypted = try SereinDeviceCrypto.encryptChunkLayer2(clear, layer1Key: key, layer2Key: layer2Key, layer1Prefix: prefix, layer2Prefix: layer2Prefix, index: index, count: count,
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
        guard let user = api.user, let device = api.currentDevice, let crypto, let layer2Crypto else { status = "Protected device setup is not ready."; return nil }
        if let existing = localFile(for: attachment) { return existing }
        var fileKeyData: Data?
        var layer2FileKeyData: Data?
        var temporary: URL?
        defer { if let count = fileKeyData?.count { fileKeyData?.resetBytes(in: 0..<count) }; if let count = layer2FileKeyData?.count { layer2FileKeyData?.resetBytes(in: 0..<count) }; if let temporary { try? FileManager.default.removeItem(at: temporary) } }
        do {
            let listData = try await api.transfersData()
            guard let records = try JSONSerialization.jsonObject(with: listData) as? [[String: Any]],
                  let transfer = records.first(where: { $0["id"] as? String == attachment.transferID }),
                  let senderUser = transfer["sender_user_id"] as? String,
                  let senderDevice = transfer["sender_device_id"] as? String,
                  let recipientUser = transfer["recipient_user_id"] as? String,
                  transfer["ready_at"] is String else { throw ChatError.transferUnavailable }
            guard recipientUser == user.id || senderUser == user.id else { throw ChatError.routeMismatch }
            let key: SymmetricKey, manifestLayer2Key: SymmetricKey
            if senderUser == user.id {
                guard senderDevice == device.id else { throw ChatError.routeMismatch }
                key = try crypto.conversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: user.id, peerDeviceID: device.id, peerJWK: crypto.publicJWK())
                manifestLayer2Key = try layer2Crypto.layer2ConversationKey(localUserID: user.id, localDeviceID: device.id, peerUserID: user.id, peerDeviceID: device.id, peerJWK: layer2Crypto.publicJWK())
            } else {
                guard senderUser == contact.user_id, let peer = peerKeys.first(where: { $0.id == senderDevice && $0.trusted }) else { throw ChatError.fingerprintRequired }
                key = peer.key; manifestLayer2Key = peer.layer2Key
            }
            let manifestVersion = transfer["manifest_crypto_version"] as? Int ?? 1
            let manifestEnvelope: [String: Any]
            if manifestVersion == 2 {
                manifestEnvelope = try crypto.decryptManifestLayer2(iv: transfer["manifest_iv"] as? String ?? "", ciphertext: transfer["manifest_ciphertext"] as? String ?? "", key: manifestLayer2Key,
                    transferID: attachment.transferID, senderUserID: senderUser, senderDeviceID: senderDevice, recipientUserID: recipientUser, recipientDeviceID: device.id)
            } else if manifestVersion == 1 {
                manifestEnvelope = ["iv": transfer["manifest_iv"] as? String ?? "", "ciphertext": transfer["manifest_ciphertext"] as? String ?? ""]
            } else { throw ChatError.manifestMismatch }
            let manifest = try crypto.decryptManifest(iv: manifestEnvelope["iv"] as? String ?? "", ciphertext: manifestEnvelope["ciphertext"] as? String ?? "", key: key,
                transferID: attachment.transferID, senderUserID: senderUser, senderDeviceID: senderDevice, recipientUserID: recipientUser, recipientDeviceID: device.id)
            let chunkCryptoVersion = transfer["chunk_crypto_version"] as? Int ?? manifest["chunk_crypto_version"] as? Int ?? 1
            guard (chunkCryptoVersion == 1 || chunkCryptoVersion == 2), (manifest["chunk_crypto_version"] as? Int ?? 1) == chunkCryptoVersion else { throw ChatError.manifestMismatch }
            let chunkSize = 256 * 1024 - (chunkCryptoVersion == 2 ? 32 : 16)
            guard manifest["version"] as? Int == 1, manifest["transfer_id"] as? String == attachment.transferID,
                  (manifest["filename"] as? String) == attachment.filename, (manifest["content_type"] as? String) == attachment.contentType,
                  (manifest["size"] as? NSNumber)?.int64Value == attachment.size,
                  let countNumber = manifest["chunk_count"] as? NSNumber, countNumber.intValue > 0,
                  countNumber.intValue <= maxChunks, countNumber.intValue == max(1, Int((attachment.size + Int64(chunkSize) - 1) / Int64(chunkSize))), countNumber.intValue == (transfer["chunk_count"] as? NSNumber)?.intValue,
                  let keyString = manifest["content_key"] as? String, let rawKey = Data(base64Encoded: keyString), rawKey.count == 32,
                  let prefixString = manifest["nonce_prefix"] as? String, let prefix = Data(base64Encoded: prefixString), prefix.count == 4 else { throw ChatError.manifestMismatch }
            let tagBytes = chunkCryptoVersion == 2 ? 32 : 16
            guard (transfer["total_ciphertext_bytes"] as? NSNumber)?.int64Value == attachment.size + Int64(countNumber.intValue) * Int64(tagBytes) else { throw ChatError.manifestMismatch }
            fileKeyData = rawKey
            let fileKey = try SereinDeviceCrypto.key(from: rawKey)
            var layer2Prefix: Data?
            var layer2Key: SymmetricKey?
            if chunkCryptoVersion == 2 {
                guard let layer2KeyString = manifest["layer2_content_key"] as? String, let layer2RawKey = Data(base64Encoded: layer2KeyString), layer2RawKey.count == 32,
                      let layer2PrefixString = manifest["layer2_nonce_prefix"] as? String, let decodedLayer2Prefix = Data(base64Encoded: layer2PrefixString), decodedLayer2Prefix.count == 4 else { throw ChatError.manifestMismatch }
                layer2FileKeyData = layer2RawKey
                layer2Key = try SereinDeviceCrypto.key(from: layer2RawKey)
                layer2Prefix = decodedLayer2Prefix
            }
            temporary = FileManager.default.temporaryDirectory.appendingPathComponent("serein-clear-\(UUID().uuidString).part")
            FileManager.default.createFile(atPath: temporary!.path, contents: nil, attributes: [.protectionKey: FileProtectionType.complete])
            let output = try FileHandle(forWritingTo: temporary!)
            defer { try? output.close() }
            var total: Int64 = 0
            for index in 0..<countNumber.intValue {
                let (ciphertext, expectedHash) = try await api.downloadTransferChunk(attachment.transferID, index: index)
                guard SereinDeviceCrypto.sha256Hex(ciphertext) == expectedHash else { throw ChatError.chunkChecksum }
                var clear: Data
                if chunkCryptoVersion == 2, let layer2Key, let layer2Prefix {
                    clear = try SereinDeviceCrypto.decryptChunkLayer2(ciphertext, layer1Key: fileKey, layer2Key: layer2Key, layer1Prefix: prefix, layer2Prefix: layer2Prefix, index: index, count: countNumber.intValue,
                        transferID: attachment.transferID, senderUserID: senderUser, senderDeviceID: senderDevice, recipientUserID: recipientUser)
                } else {
                    clear = try SereinDeviceCrypto.decryptChunk(ciphertext, key: fileKey, noncePrefix: prefix, index: index, count: countNumber.intValue,
                        transferID: attachment.transferID, senderUserID: senderUser, senderDeviceID: senderDevice, recipientUserID: recipientUser)
                }
                defer { clear.resetBytes(in: 0..<clear.count) }
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
