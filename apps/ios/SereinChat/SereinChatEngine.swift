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
    let recipientCount: Int
    let deliveredCount: Int
    let readCount: Int
    let attachment: SereinEncryptedAttachment?
    let isSystem: Bool
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
    @Published private(set) var historySyncRequests:[[String:Any]]=[]
    @Published private(set) var mainDeviceID:String?=nil
    @Published private(set) var mainDevicePlatform:String?=nil
    @Published private(set) var mainDeviceOnline=false
    @Published private(set) var currentDevicePlatform:String?=nil
    @Published private(set) var preferredMobileDeviceID:String?=nil
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
    private var keyEpoch = 1
    private var cursorTime: String?
    private var cursorID: String?
    private var readMarkedIDs = Set<String>()
    private var lastReceiptRefresh = Date.distantPast
    private var lastExpiryRefresh = Date.distantPast
    private var expiryCursorTime: String?
    private var expiryCursorID: String?
    private var deletionCursorTime: String?
    private var deletionCursorID: String?
    private var pollRunning = false
    private var pendingRetryRunning = false
    private var nextPendingRetryAt = Date.distantPast
    private let pendingRetryInterval: TimeInterval = 30
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
            let signingKey = try SereinDeviceCrypto.loadOrCreateSigning(userID:user.id,deviceID:device.id)
            let localStore = try SereinLocalStore(accountID: user.id)
            crypto = deviceCrypto; layer2Crypto = deviceLayer2Crypto; local = localStore
            let expiryCursor=localStore.metadata("expiryCursor:\(contact.user_id)");expiryCursorTime=expiryCursor?["after_created_at"] as? String;expiryCursorID=expiryCursor?["after_id"] as? String;let deletionCursor=localStore.metadata("messageDeletionCursor");deletionCursorTime=deletionCursor?["after_created_at"] as? String;deletionCursorID=deletionCursor?["after_id"] as? String
            if contact.isDeleted { loadMessages(); ready = true; status = "Archived conversation · this account was deleted · read-only"; return }
            ownFingerprint = try SereinDeviceCrypto.fingerprintBundle(layer1: deviceCrypto.publicJWK(), layer2: deviceLayer2Crypto.publicJWK())
            let ratchetVersion = SereinCoreBridge.version == "unavailable" ? 2 : 3
            let signingJWK=SereinDeviceCrypto.signingPublicJWK(signingKey),rotationTimestamp=Int(Date().timeIntervalSince1970);let proof=try SereinDeviceCrypto.signDeviceKeyRotation(signingKey,userID:user.id,deviceID:device.id,oldFingerprint:"",newFingerprint:ownFingerprint,timestamp:rotationTimestamp,epoch:1)
            let registration = try await api.registerDeviceKey(deviceCrypto.publicJWK(), layer2PublicJWK: deviceLayer2Crypto.publicJWK(), signingPublicJWK:signingJWK, rotationProof:proof, rotationTimestamp:rotationTimestamp, keyEpoch:1, ratchetVersion: ratchetVersion)
            keyEpoch=registration["key_epoch"] as? Int ?? 1
            guard registration["fingerprint"] as? String == ownFingerprint else {
                throw SereinDeviceCrypto.CryptoError.invalidPublicKey
            }
            try await refreshPeerKeysForSend()
            loadMessages()
            ready = true; status = peerStatus
            await retryPendingIfNeeded(force: true)
            await poll()
            notificationsArmed = true
        } catch { status = error.localizedDescription }
    }

    var peerStatus: String {
        if activeDevices.isEmpty { return "No active recipient devices are available." }
        if peerKeys.count < activeDevices.count { return "\(activeDevices.count - peerKeys.count) active device(s) have not published a key." }
        let trusted = peerKeys.filter(\.trusted).count
        return trusted == activeDevices.count ? "All \(trusted) recipient-device key bundles are app-checked and locally pinned." : "\(activeDevices.count - trusted) recipient-device key changes or capability downgrades are blocked."
    }

    func rotateDeviceKeys() async throws {
        guard let user=api.user,let device=api.currentDevice,let oldLayer1=crypto,let oldLayer2=layer2Crypto else{throw ChatError.deviceUnavailable}
        let oldFingerprint=ownFingerprint,nextEpoch=keyEpoch+1,timestamp=Int(Date().timeIntervalSince1970)
        let staged1=try SereinDeviceCrypto.stageRotatedKey(userID:user.id,deviceID:device.id,layer2:false,epoch:keyEpoch)
        let staged2: (SereinDeviceCrypto,Data?)
        do { staged2=try SereinDeviceCrypto.stageRotatedKey(userID:user.id,deviceID:device.id,layer2:true,epoch:keyEpoch) }
        catch { try? SereinDeviceCrypto.restoreKeyMaterial(staged1.1,userID:user.id,deviceID:device.id,layer2:false);throw error }
        do {
            let nextFingerprint=try SereinDeviceCrypto.fingerprintBundle(layer1:staged1.0.publicJWK(),layer2:staged2.0.publicJWK()),signing=try SereinDeviceCrypto.loadOrCreateSigning(userID:user.id,deviceID:device.id),signingJWK=SereinDeviceCrypto.signingPublicJWK(signing),proof=try SereinDeviceCrypto.signDeviceKeyRotation(signing,userID:user.id,deviceID:device.id,oldFingerprint:oldFingerprint,newFingerprint:nextFingerprint,timestamp:timestamp,epoch:nextEpoch)
            let response=try await api.registerDeviceKey(staged1.0.publicJWK(),layer2PublicJWK:staged2.0.publicJWK(),signingPublicJWK:signingJWK,rotationProof:proof,rotationTimestamp:timestamp,keyEpoch:nextEpoch,ratchetVersion:3)
            guard response["fingerprint"] as? String==nextFingerprint,response["key_epoch"] as? Int==nextEpoch else{throw ChatError.keyDirectoryMismatch}
            crypto=staged1.0;layer2Crypto=staged2.0;ownFingerprint=nextFingerprint;keyEpoch=nextEpoch;peerKeys=[];try await refreshPeerKeys()
        } catch {
            try? SereinDeviceCrypto.restoreKeyMaterial(staged1.1,userID:user.id,deviceID:device.id,layer2:false)
            try? SereinDeviceCrypto.restoreKeyMaterial(staged2.1,userID:user.id,deviceID:device.id,layer2:true)
            crypto=oldLayer1;layer2Crypto=oldLayer2;throw error
        }
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
            var old = local?.previousFingerprint(userID: contact.user_id, deviceID: target.id) ?? ""
            var oldVersion = local?.previousRatchetVersion(userID: contact.user_id, deviceID: target.id) ?? 2
            let firstSeen = old.isEmpty,signingJWK=entry["signing_public_key"] as? [String:Any],keyEpoch=entry["key_epoch"] as? Int ?? 1
            let pinnedSigner=local?.previousSigningPublicKey(userID:contact.user_id,deviceID:target.id),pinnedEpoch=local?.previousKeyEpoch(userID:contact.user_id,deviceID:target.id) ?? 0
            let signerMatches:Bool = { guard let signingJWK else{return pinnedSigner == nil};guard let pinnedSigner else{return true};return signingJWK["x"] as? String == pinnedSigner["x"] as? String && signingJWK["y"] as? String == pinnedSigner["y"] as? String }()
            let sameFingerprint=old==fingerprint,capabilityAccepted=(2...3).contains(oldVersion)&&ratchetVersion>=oldVersion
            let legacyBootstrapAccepted:Bool = { guard !firstSeen,sameFingerprint,pinnedSigner==nil,let signingJWK else{return true};guard let proof=entry["rotation_proof"] as? String else{return false};return SereinDeviceCrypto.verifyDeviceKeyRotation(signingJWK:signingJWK,userID:contact.user_id,deviceID:target.id,oldFingerprint:"",newFingerprint:fingerprint,timestamp:entry["rotation_timestamp"] as? Int ?? 0,epoch:1,proof:proof) }()
            var continuityAccepted=false
            if !firstSeen && !sameFingerprint && signerMatches,let pinnedSigner,pinnedEpoch>0 {
                var expectedFingerprint=old,expectedEpoch=pinnedEpoch
                for step in (entry["rotation_chain"] as? [[String:Any]] ?? []).sorted(by:{($0["key_epoch"] as? Int ?? 0)<($1["key_epoch"] as? Int ?? 0)}) where ($0["key_epoch"] as? Int ?? 0)>pinnedEpoch {
                    guard let epoch=step["key_epoch"] as? Int,epoch==expectedEpoch+1,let oldValue=step["old_fingerprint"] as? String,oldValue==expectedFingerprint,let newValue=step["new_fingerprint"] as? String,let proof=step["proof"] as? String,SereinDeviceCrypto.verifyDeviceKeyRotation(signingJWK:pinnedSigner,userID:contact.user_id,deviceID:target.id,oldFingerprint:oldValue,newFingerprint:newValue,timestamp:step["timestamp"] as? Int ?? 0,epoch:epoch,proof:proof) else { continuityAccepted=false;break }
                    expectedEpoch=epoch;expectedFingerprint=newValue;continuityAccepted=expectedEpoch==keyEpoch&&expectedFingerprint==fingerprint
                }
            }
            let trustedBundle=firstSeen||(sameFingerprint&&capabilityAccepted&&signerMatches&&legacyBootstrapAccepted)||(continuityAccepted&&capabilityAccepted)
            if firstSeen { try local?.trust(userID:contact.user_id,deviceID:target.id,fingerprint:fingerprint,ratchetVersion:ratchetVersion,keyEpoch:keyEpoch,signingPublicJWK:signingJWK);old=fingerprint;oldVersion=ratchetVersion }
            else if trustedBundle { try local?.trust(userID:contact.user_id,deviceID:target.id,fingerprint:fingerprint,ratchetVersion:ratchetVersion,keyEpoch:keyEpoch,signingPublicJWK:pinnedSigner ?? signingJWK);old=fingerprint;oldVersion=ratchetVersion }
            next.append(SereinPeerKey(id: target.id, name: target.name, fingerprint: fingerprint, previousFingerprint: firstSeen ? "" : old,
                ratchetVersion: ratchetVersion, previousRatchetVersion: oldVersion, publicJWK: jwk, layer2PublicJWK: layer2JWK,
                trusted: trustedBundle, key: key, layer2Key: layer2Key))
        }
        activeDevices = latestDevices
        peerKeys = next
        status = peerStatus
    }

    func refreshHistorySync() async {
        do { let directory=try await api.ownDeviceKeyDirectory();mainDeviceID=directory["main_device_id"] as? String;mainDevicePlatform=directory["main_device_platform"] as? String;mainDeviceOnline=directory["main_device_online"] as? Bool ?? false;currentDevicePlatform=directory["current_device_platform"] as? String;preferredMobileDeviceID=directory["preferred_mobile_device_id"] as? String;historySyncRequests=try await api.historySyncRequests() }
        catch { status="History sync unavailable: \(error.localizedDescription)" }
    }
    func requestHistorySync() async throws { _=try await api.createHistorySyncRequest();await refreshHistorySync() }
    func promoteCurrentDeviceToMain() async throws { try await api.promoteCurrentDeviceToMain();await refreshHistorySync() }
    private func pinOwnSyncDevice(_ entry:[String:Any])throws->[String:Any] {
        guard let user=api.user,let deviceID=entry["device_id"] as? String,let layer1=entry["public_key"] as? [String:Any],let layer2=entry["layer2_public_key"] as? [String:Any] else{throw ChatError.keyDirectoryMismatch}
        let fingerprint=try SereinDeviceCrypto.fingerprintBundle(layer1:layer1,layer2:layer2);guard fingerprint==entry["fingerprint"] as? String else{throw ChatError.keyDirectoryMismatch}
        let pin=local?.previousFingerprint(userID:user.id,deviceID:deviceID) ?? "",signing=entry["signing_public_key"] as? [String:Any],pinnedSigner=local?.previousSigningPublicKey(userID:user.id,deviceID:deviceID),epoch=entry["key_epoch"] as? Int ?? 1,pinnedEpoch=local?.previousKeyEpoch(userID:user.id,deviceID:deviceID) ?? 0,first=pin.isEmpty,same=pin==fingerprint
        let signerMatches:Bool={guard let signing else{return pinnedSigner==nil};guard let pinnedSigner else{return true};return signing["x"] as? String==pinnedSigner["x"] as? String && signing["y"] as? String==pinnedSigner["y"] as? String}()
        let bootstrap:Bool={guard !first,same,pinnedSigner==nil,let signing,let proof=entry["rotation_proof"] as? String else{return true};return SereinDeviceCrypto.verifyDeviceKeyRotation(signingJWK:signing,userID:user.id,deviceID:deviceID,oldFingerprint:"",newFingerprint:fingerprint,timestamp:entry["rotation_timestamp"] as? Int ?? 0,epoch:1,proof:proof)}()
        var accepted=first||(same&&signerMatches&&bootstrap)
        if !first && !same && signerMatches,let pinnedSigner,pinnedEpoch>0 {var expected=pin,expectedEpoch=pinnedEpoch;for step in (entry["rotation_chain"] as? [[String:Any]] ?? []).sorted(by:{($0["key_epoch"] as? Int ?? 0)<($1["key_epoch"] as? Int ?? 0)}) where ($0["key_epoch"] as? Int ?? 0)>pinnedEpoch {guard let next=step["key_epoch"] as? Int,next==expectedEpoch+1,let old=step["old_fingerprint"] as? String,old==expected,let new=step["new_fingerprint"] as? String,let proof=step["proof"] as? String,SereinDeviceCrypto.verifyDeviceKeyRotation(signingJWK:pinnedSigner,userID:user.id,deviceID:deviceID,oldFingerprint:old,newFingerprint:new,timestamp:step["timestamp"] as? Int ?? 0,epoch:next,proof:proof) else{accepted=false;break};expected=new;expectedEpoch=next;accepted=expected==fingerprint&&expectedEpoch==epoch}}
        guard accepted else{throw ChatError.keyDirectoryMismatch};let version=entry["ratchet_version"] as? Int ?? 2;if version < (local?.previousRatchetVersion(userID:user.id,deviceID:deviceID) ?? 2){throw ChatError.keyDirectoryMismatch};try local?.trust(userID:user.id,deviceID:deviceID,fingerprint:fingerprint,ratchetVersion:version,keyEpoch:epoch,signingPublicJWK:pinnedSigner ?? signing);return entry
    }
    private func normalizedHistoryMessages()throws->[[String:Any]] {
        guard let local else{throw ChatError.deviceUnavailable};let rows=local.allMessages();guard rows.count<=100_000 else{throw ChatError.historyUnavailable};var result=[[String:Any]]();result.reserveCapacity(rows.count);for var row in rows {guard let id=row["id"] as? String,!id.isEmpty,id.utf8.count<=128,let conversation=row["conversation_id"] as? String,UUID(uuidString:conversation) != nil,let created=row["created_at"] as? String,SereinLocalStore.validHistoryTimestamp(created),let status=row["status"] as? String,["pending","accepted","sent","delivered","read","received","expired"].contains(status) else{throw ChatError.historyUnavailable};for key in ["id","conversation_id","created_at","status","envelopes","receipt","recipient_count","delivered_count","read_count"]{row.removeValue(forKey:key)};result.append(["id":id,"conversation_id":conversation,"created_at":created,"status":status,"payload":row])};return result
    }
    func sendHistorySync(_ request:[String:Any]) async throws {
        guard let user=api.user,let device=api.currentDevice,let crypto else{throw ChatError.deviceUnavailable};let requestID=request["id"] as? String ?? "",childID=request["child_device_id"] as? String ?? "",directory=try await api.ownDeviceKeyDirectory();guard directory["main_device_id"] as? String==device.id else{throw ChatError.keyDirectoryMismatch};guard let child=(directory["devices"] as? [[String:Any]])?.first(where:{$0["device_id"] as? String==childID}) else{throw ChatError.deviceListChanged};_ = try pinOwnSyncDevice(child)
        try await refreshMessageDeletions()
        let records=try normalizedHistoryMessages();var batches=[[ [String:Any] ]](),current=[[String:Any]]();for row in records {current.append(row);let size=(try JSONSerialization.data(withJSONObject:current)).count;if size>300*1024{current.removeLast();if current.isEmpty{throw ChatError.historyUnavailable};batches.append(current);current=[row]}};if !current.isEmpty||batches.isEmpty{batches.append(current)};guard batches.count<=128 else{throw ChatError.historyUnavailable};let count=batches.count
        for (index,rows) in batches.enumerated(){let payload:[String:Any]=["schema_version":1,"account_id":user.id,"main_device_id":device.id,"child_device_id":childID,"request_id":requestID,"batch_index":index,"batch_count":count,"messages":rows],clear=try JSONSerialization.data(withJSONObject:payload),key=try crypto.deriveHistorySyncKey(accountID:user.id,localDeviceID:device.id,peerDeviceID:childID,peerJWK:child["public_key"] as? [String:Any] ?? [:],mainDeviceID:device.id,childDeviceID:childID,requestID:requestID,index:index,count:count);let envelope=try crypto.encryptHistorySyncBatch(clear,key:key,accountID:user.id,mainDeviceID:device.id,childDeviceID:childID,requestID:requestID,index:index,count:count),canonical=try JSONSerialization.data(withJSONObject:envelope,options:[.sortedKeys]),ciphertext=String(data:canonical,encoding:.utf8) ?? "",digest=try SereinDeviceCrypto.historySyncDigest(envelope);try await api.putHistorySyncBatch(requestID,values:["batch_index":index,"batch_count":count,"ciphertext_json":ciphertext,"digest":digest])}
        await refreshHistorySync()
    }
    func receiveHistorySync(_ request:[String:Any]) async throws -> Int {
        guard let user=api.user,let device=api.currentDevice,let crypto,let local else{throw ChatError.deviceUnavailable};let requestID=request["id"] as? String ?? "",mainID=request["main_device_id"] as? String ?? "",directory=try await api.ownDeviceKeyDirectory();guard directory["main_device_id"] as? String==mainID,let main=(directory["devices"] as? [[String:Any]])?.first(where:{$0["device_id"] as? String==mainID}) else{throw ChatError.keyDirectoryMismatch};_ = try pinOwnSyncDevice(main);let response=try await api.historySyncBatches(requestID);guard response["status"] as? String=="ready",let count=response["batch_count"] as? Int,(1...128).contains(count),let batches=response["batches"] as? [[String:Any]],batches.count==count else{throw ChatError.historyUnavailable};var records=[[String:Any]]()
        for (index,batch) in batches.enumerated(){guard batch["batch_index"] as? Int==index,batch["batch_count"] as? Int==count,let envelope=batch["ciphertext"] as? [String:Any],try SereinDeviceCrypto.historySyncDigest(envelope)==batch["digest"] as? String else{throw ChatError.keyDirectoryMismatch};let key=try crypto.deriveHistorySyncKey(accountID:user.id,localDeviceID:device.id,peerDeviceID:mainID,peerJWK:main["public_key"] as? [String:Any] ?? [:],mainDeviceID:mainID,childDeviceID:device.id,requestID:requestID,index:index,count:count),clear=try crypto.decryptHistorySyncBatch(envelope,key:key,accountID:user.id,mainDeviceID:mainID,childDeviceID:device.id,requestID:requestID,index:index,count:count),payload=try JSONSerialization.jsonObject(with:clear) as? [String:Any];guard payload?["schema_version"] as? Int==1,payload?["account_id"] as? String==user.id,payload?["main_device_id"] as? String==mainID,payload?["child_device_id"] as? String==device.id,payload?["request_id"] as? String==requestID,payload?["batch_index"] as? Int==index,payload?["batch_count"] as? Int==count,let items=payload?["messages"] as? [[String:Any]] else{throw ChatError.keyDirectoryMismatch};records.append(contentsOf:items)}
        try await refreshMessageDeletions()
        let added=try local.mergeHistorySyncMessages(records);try await api.acknowledgeHistorySync(requestID);await refreshHistorySync();loadMessages();return added
    }
    func cancelHistorySync(_ request:[String:Any]) async throws {guard let id=request["id"] as? String else{throw ChatError.historyUnavailable};try await api.cancelHistorySync(id);await refreshHistorySync()}
    private func refreshPeerKeysForSend() async throws {
        do { try await refreshPeerKeys() }
        catch ChatError.deviceListChanged { try await refreshPeerKeys() }
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
        try await refreshPeerKeysForSend()
        guard !archived else { throw ChatError.contactUnavailable }
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
        status = "Encrypted message sent · accepted by all recipient devices."
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

    func retryPendingIfNeeded(force: Bool = false) async {
        guard !archived, let local, !pendingRetryRunning, force || Date() >= nextPendingRetryAt else { return }
        pendingRetryRunning = true
        nextPendingRetryAt = Date().addingTimeInterval(pendingRetryInterval)
        defer { pendingRetryRunning = false }
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

    func poll(markAsRead: Bool = true) async {
        guard ready, !archived, !pollRunning, let user = api.user, let device = api.currentDevice, let crypto, let local else { return }
        pollRunning = true; defer { pollRunning = false }
        do {
            try await refreshMessageDeletions()
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
                    if local.containsDeleted(messageID:id){cursorTime=created;cursorID=id;continue}
                    if local.contains(messageID: id) { try await api.acknowledgeMessage(id); cursorTime = created; cursorID = id; continue }
                    guard let peer = peerKeys.first(where: { $0.id == senderDeviceID }), peer.trusted else {
                        status = "A message is held because the sender-device key changed or is not locally pinned."; stopped = true; break
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
            if markAsRead {
                let ids=local.messages(for:contact.user_id).compactMap { row -> String? in
                    guard row["mine"] as? Bool != true, let id=row["id"] as? String, !readMarkedIDs.contains(id) else { return nil }
                    return id
                }.prefix(200)
                if !ids.isEmpty { try await api.markMessagesRead(Array(ids)); readMarkedIDs.formUnion(ids) }
            }
            if Date().timeIntervalSince(lastReceiptRefresh)>=12 { await refreshOutgoingReceipts(); lastReceiptRefresh=Date() }
            if Date().timeIntervalSince(lastExpiryRefresh)>=30 { await refreshExpiredNotices(); lastExpiryRefresh=Date() }
        } catch { status = "Secure message sync paused; it will retry." }
    }

    private func cleanupDeletedTransfer(_ transferID:String,accountID:String){if SereinAttachmentStore.shared.deleteTransfer(accountID:accountID,transferID:transferID){try? local?.markTransferDeletionComplete(transferID)}}
    private func deletionExpiryMillis(_ value:String)->Int64 { let formatter=ISO8601DateFormatter();formatter.formatOptions=[.withInternetDateTime,.withFractionalSeconds];if let date=formatter.date(from:value){return Int64(date.timeIntervalSince1970*1000)};formatter.formatOptions=[.withInternetDateTime];if let date=formatter.date(from:value){return Int64(date.timeIntervalSince1970*1000)};return Int64(Date().timeIntervalSince1970*1000)+Int64(90*24*60*60*1000) }
    private func retryPendingMediaCleanup(accountID:String){for transfer in local?.pendingTransferDeletions() ?? []{cleanupDeletedTransfer(transfer,accountID:accountID)}}
    func syncMessageDeletions() async { do{try await refreshMessageDeletions();loadMessages()}catch{status="Deletion sync will retry when this conversation is available."} }
    func syncMessageDeletionsForHistoryOperation() async throws { guard ready,!archived,local != nil else{throw ChatError.historyUnavailable};try await refreshMessageDeletions();loadMessages() }
    private func refreshMessageDeletions() async throws {
        guard let local else{return};retryPendingMediaCleanup(accountID:api.user?.id ?? "")
        for _ in 0..<40 { let data=try await api.messageDeletions(afterCreatedAt:deletionCursorTime,afterID:deletionCursorID);guard let page=try JSONSerialization.jsonObject(with:data) as? [String:Any],let rows=page["deletions"] as? [[String:Any]],!rows.isEmpty else{return};for row in rows {guard let id=row["message_id"] as? String,let time=row["deleted_at"] as? String else{continue};let transfers=row["transfer_ids"] as? [String] ?? [];try local.deleteMessage(messageID:id,transferIDs:transfers,expiresAtMillis:deletionExpiryMillis(row["expires_at"] as? String ?? ""));for transfer in transfers {cleanupDeletedTransfer(transfer,accountID:api.user?.id ?? "")};deletionCursorTime=time;deletionCursorID=id;try local.setMetadata(["after_created_at":time,"after_id":id],for:"messageDeletionCursor")};if page["has_more"] as? Bool != true{return} }
    }
    func deleteMessages(_ ids:Set<String>,scope:String) async throws {
        guard let local,let account=api.user?.id else{throw ChatError.historyUnavailable};let selected=local.messages(for:contact.user_id).filter{ids.contains($0["id"] as? String ?? "")};guard selected.count==ids.count else{throw ChatError.historyUnavailable};let records:[[String:Any]]=selected.map{row in let attachment=row["attachment"] as? [String:Any];let transfer=(attachment?["transfer_id"] as? String).map{[$0]} ?? [];return ["id":row["id"] ?? "","conversation_id":contact.user_id,"transfer_ids":transfer]};try await api.deleteMessages(scope:scope,messages:records);for row in records {guard let id=row["id"] as? String else{continue};let transfers=row["transfer_ids"] as? [String] ?? [];try local.deleteMessage(messageID:id,transferIDs:transfers);for transfer in transfers {cleanupDeletedTransfer(transfer,accountID:account)}};loadMessages()
    }
    private func refreshExpiredNotices() async {
        guard let local else { return }
        do {
            let data=try await api.expiredMessages(contactID:contact.user_id,afterCreatedAt:expiryCursorTime,afterID:expiryCursorID)
            guard let payload=try JSONSerialization.jsonObject(with:data) as? [String:Any],let rows=payload["items"] as? [[String:Any]] else { return }
            for item in rows {
                guard let messageID=item["id"] as? String,let expiredAt=item["expired_at"] as? String else { continue }
                let noticeID="expired-notice:\(messageID)"
                if !local.contains(messageID:noticeID) {
                    let sender=item["display_name"] as? String ?? item["username"] as? String ?? "a contact"
                    let notice:[String:Any] = ["id":noticeID,"conversation_id":contact.user_id,"created_at":expiredAt,"text":"A message from \(sender) was removed because this device was inactive beyond the delivery window.","sender":sender,"mine":false,"status":"received","system":true,"expiry_notice":true,"expired_message_id":messageID]
                    try local.save(notice)
                }
                expiryCursorTime=expiredAt;expiryCursorID=messageID
                try local.setMetadata(["after_created_at":expiredAt,"after_id":messageID],for:"expiryCursor:\(contact.user_id)")
            }
            if !rows.isEmpty { loadMessages() }
        } catch { /* Retry the same cursor next foreground poll; never advance before local save. */ }
    }
    func retryExpiredMessage(_ messageID: String) async {
        guard let local else { status="Local history is unavailable.";return }
        guard let row=local.messages(for:contact.user_id).first(where:{$0["id"] as? String==messageID}),row["mine"] as? Bool==true,row["status"] as? String=="expired" else { status="Expired message is unavailable for retry.";return }
        if row["attachment"] != nil { status="Select the original attachment again; its server copy may have expired.";return }
        await sendText(row["text"] as? String ?? "")
    }

    private func refreshOutgoingReceipts() async {
        guard let local else { return }
        let outgoing=messages.filter { $0.mine && ["accepted","delivered","read"].contains($0.status) }.suffix(200)
        let ids=outgoing.map(\.id);guard !ids.isEmpty else { return }
        do {
            let data=try await api.messageReceipts(ids:ids)
            guard let payload=try JSONSerialization.jsonObject(with:data) as? [String:Any],let receipts=payload["items"] as? [[String:Any]] else { return }
            let lookup=Dictionary(uniqueKeysWithValues:receipts.compactMap { row -> (String,[String:Any])? in guard let id=row["id"] as? String else { return nil };return(id,row) })
            var changed=false
            for var row in local.messages(for:contact.user_id) where row["mine"] as? Bool == true {
                guard let id=row["id"] as? String,let receipt=lookup[id] else { continue }
                let recipients=(receipt["recipient_count"] as? NSNumber)?.intValue ?? 0
                let delivered=(receipt["delivered_count"] as? NSNumber)?.intValue ?? 0
                let read=(receipt["read_count"] as? NSNumber)?.intValue ?? 0
                let expired=(receipt["expired_count"] as? NSNumber)?.intValue ?? 0
                let status=read>0 ? "read" : (delivered>0 ? "delivered" : (expired>0 ? "expired" : "accepted"))
                if (row["status"] as? String) != status || (row["delivered_count"] as? Int ?? -1) != delivered || (row["read_count"] as? Int ?? -1) != read || (row["expired_count"] as? Int ?? -1) != expired {
                    row["status"]=status;row["recipient_count"]=recipients;row["delivered_count"]=delivered;row["read_count"]=read;row["expired_count"]=expired;row["expired_at"]=receipt["expired_at"]
                    try local.save(row);changed=true
                }
            }
            if changed { loadMessages() }
        } catch { /* Receipt polling is best-effort; the durable message remains unchanged. */ }
    }

    func sendFile(url: URL, filename: String, contentType: String) async {
        guard !contact.isDeleted && !archived else { status = "This archived conversation is read-only."; return }
        guard ready, let user = api.user, let device = api.currentDevice, let crypto, let layer2Crypto else { status = "Protected device setup is not ready."; return }
        var contentKeyData: Data
        var layer2ContentKeyData: Data
        do { contentKeyData = try SereinDeviceCrypto.randomData(count: 32); layer2ContentKeyData = try SereinDeviceCrypto.randomData(count: 32) } catch { status = error.localizedDescription; return }
        defer { contentKeyData.resetBytes(in: 0..<contentKeyData.count); layer2ContentKeyData.resetBytes(in: 0..<layer2ContentKeyData.count) }
        do {
            try await refreshPeerKeysForSend()
            guard !archived else { throw ChatError.contactUnavailable }
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

    func localFile(for attachment: SereinEncryptedAttachment) -> URL? { if local?.containsDeletedTransfer(transferID:attachment.transferID)==true{return nil};return SereinAttachmentStore.shared.existing(accountID: api.user?.id ?? "", transferID: attachment.transferID, filename: attachment.filename, expectedBytes: attachment.size) }

    func download(_ attachment: SereinEncryptedAttachment) async -> URL? {
        guard let user = api.user, let device = api.currentDevice, let crypto, let layer2Crypto else { status = "Protected device setup is not ready."; return nil }
        if local?.containsDeletedTransfer(transferID:attachment.transferID)==true { status="This attachment was deleted.";return nil }
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
            if local?.containsDeletedTransfer(transferID:attachment.transferID)==true { throw ChatError.transferUnavailable }
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
                status: row["status"] as? String ?? "received", recipientCount: row["recipient_count"] as? Int ?? 0,
                deliveredCount: row["delivered_count"] as? Int ?? 0, readCount: row["read_count"] as? Int ?? 0, attachment: attachment, isSystem: row["system"] as? Bool ?? false)
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
        case deviceUnavailable, contactUnavailable, keyDirectoryMismatch, deviceListChanged, noRecipientDevices, historyUnavailable
        case fingerprintRequired, fileUnavailable, fileTooLarge, fileChanged, transferUnavailable, routeMismatch
        case manifestMismatch, chunkChecksum, invalidAttachment
        var errorDescription: String? {
            switch self {
            case .deviceUnavailable: return "Protected device setup is not ready."
            case .contactUnavailable: return "This account is no longer an accepted contact."
            case .keyDirectoryMismatch: return "The authenticated device-key directory did not match this contact."
            case .deviceListChanged: return "The signed-in device list is still changing. Retry shortly; changed pinned keys remain blocked."
            case .noRecipientDevices: return "No active recipient devices are available."
            case .historyUnavailable: return "The encrypted history-sync transfer is unavailable or exceeds its safe bounds."
            case .fingerprintRequired: return "A recipient-device key changed or is not locally pinned; sending is blocked."
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
