import CryptoKit
import Foundation
import Security

/// Built-in CryptoKit implementation of P-256/HKDF-SHA256/AES-GCM for
/// independent device-bound Layer 1 and Layer 2 chat keys. Private keys stay local.
final class SereinDeviceCrypto {
    private enum PrivateMaterial {
        case secure(SecureEnclave.P256.KeyAgreement.PrivateKey)
        case software(P256.KeyAgreement.PrivateKey)

        var publicKey: P256.KeyAgreement.PublicKey {
            switch self { case .secure(let key): return key.publicKey; case .software(let key): return key.publicKey }
        }
        func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
            switch self {
            case .secure(let key): return try key.sharedSecretFromKeyAgreement(with: peer)
            case .software(let key): return try key.sharedSecretFromKeyAgreement(with: peer)
            }
        }
        var persistedRepresentation: Data {
            switch self {
            case .secure(let key): return Data([1]) + key.dataRepresentation
            case .software(let key): return Data([0]) + key.rawRepresentation
            }
        }
    }

    private let privateMaterial: PrivateMaterial
    private static let fingerprintPrefix = Data("Serein ECDH P-256 public key v1\0".utf8)

    private init(_ privateMaterial: PrivateMaterial) { self.privateMaterial = privateMaterial }

    static func loadOrCreate(userID: String, deviceID: String) throws -> SereinDeviceCrypto { try loadOrCreate(userID: userID, deviceID: deviceID, layer2: false) }
    static func loadOrCreateLayer2(userID: String, deviceID: String) throws -> SereinDeviceCrypto { try loadOrCreate(userID: userID, deviceID: deviceID, layer2: true) }
    private static func loadOrCreate(userID: String, deviceID: String, layer2: Bool) throws -> SereinDeviceCrypto {
        let purpose = layer2 ? "device-layer2-key-v1" : "device-key-v1"
        let account = "\(purpose):\(userID):\(deviceID)"
        if let stored = try SereinKeychain.read(account: account), let first = stored.first {
            let representation = Data(stored.dropFirst())
            if first == 1, SecureEnclave.isAvailable {
                return SereinDeviceCrypto(.secure(try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: representation)))
            }
            if first == 0 { return SereinDeviceCrypto(.software(try P256.KeyAgreement.PrivateKey(rawRepresentation: representation))) }
            throw CryptoError.storedKeyUnavailable
        }
        let created: PrivateMaterial
        if SecureEnclave.isAvailable, let secure = try? SecureEnclave.P256.KeyAgreement.PrivateKey() {
            created = .secure(secure)
        } else { created = .software(P256.KeyAgreement.PrivateKey()) }
        try SereinKeychain.write(created.persistedRepresentation, account: account)
        return SereinDeviceCrypto(created)
    }

    func publicJWK() -> [String: String] {
        let raw = privateMaterial.publicKey.rawRepresentation
        let x = raw.subdata(in: 1..<33), y = raw.subdata(in: 33..<65)
        return ["kty": "EC", "crv": "P-256", "x": Self.base64URL(x), "y": Self.base64URL(y)]
    }

    static func fingerprint(_ jwk: [String: Any]) throws -> String {
        guard jwk["kty"] as? String == "EC", jwk["crv"] as? String == "P-256",
              let xText = jwk["x"] as? String, let yText = jwk["y"] as? String,
              let x = base64URLDecode(xText), let y = base64URLDecode(yText), x.count == 32, y.count == 32 else {
            throw CryptoError.invalidPublicKey
        }
        return SHA256.hash(data: fingerprintPrefix + x + y).map { String(format: "%02x", $0) }.joined()
    }

    static func fingerprintBundle(layer1: [String: Any], layer2: [String: Any]) throws -> String {
        func coordinates(_ jwk: [String: Any]) throws -> Data {
            guard jwk["kty"] as? String == "EC", jwk["crv"] as? String == "P-256",
                  let xText = jwk["x"] as? String, let yText = jwk["y"] as? String,
                  let x = base64URLDecode(xText), let y = base64URLDecode(yText), x.count == 32, y.count == 32 else { throw CryptoError.invalidPublicKey }
            return x + y
        }
        let first = try coordinates(layer1)
        let second = try coordinates(layer2)
        let material = Data("Serein ECDH P-256 device key bundle v2\0".utf8) + first + second
        return SHA256.hash(data: material).map { String(format: "%02x", $0) }.joined()
    }

    func conversationKey(localUserID: String, localDeviceID: String, peerUserID: String,
                         peerDeviceID: String, peerJWK: [String: Any]) throws -> SymmetricKey {
        try deriveDevicePairKey(localUserID: localUserID, localDeviceID: localDeviceID, peerUserID: peerUserID, peerDeviceID: peerDeviceID, peerJWK: peerJWK, layer2: false)
    }
    func layer2ConversationKey(localUserID: String, localDeviceID: String, peerUserID: String,
                               peerDeviceID: String, peerJWK: [String: Any]) throws -> SymmetricKey {
        try deriveDevicePairKey(localUserID: localUserID, localDeviceID: localDeviceID, peerUserID: peerUserID, peerDeviceID: peerDeviceID, peerJWK: peerJWK, layer2: true)
    }
    private func deriveDevicePairKey(localUserID: String, localDeviceID: String, peerUserID: String,
                                     peerDeviceID: String, peerJWK: [String: Any], layer2: Bool) throws -> SymmetricKey {
        guard let xText = peerJWK["x"] as? String, let yText = peerJWK["y"] as? String,
              let x = Self.base64URLDecode(xText), let y = Self.base64URLDecode(yText), x.count == 32, y.count == 32 else {
            throw CryptoError.invalidPublicKey
        }
        let point = Data([4]) + x + y
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: point)
        let secret = try privateMaterial.sharedSecret(with: peer)
        let parties = ["\(localUserID):\(localDeviceID)", "\(peerUserID):\(peerDeviceID)"].sorted()
        let context = parties.joined(separator: "|")
        let saltLabel = layer2 ? "serein-e2ee-layer2-salt-v1" : "serein-e2ee-salt-v1"
        let infoLabel = layer2 ? "serein-e2ee-layer2-session-v1" : "serein-e2ee-conversation-v1"
        let salt = Data(SHA256.hash(data: Data("\(saltLabel)|\(context)".utf8)))
        let info = Data("\(infoLabel)|\(context)".utf8)
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
    }

    func encryptMessage(_ content: [String: Any], key: SymmetricKey, conversationID: String, messageID: String,
                        senderUserID: String, senderDeviceID: String, recipientUserID: String, recipientDeviceID: String) throws -> [String: String] {
        let aad = Self.jsonArray(["serein-message-v1", conversationID, messageID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let clear = try JSONSerialization.data(withJSONObject: content)
        return try seal(clear, key: key, aad: aad)
    }

    func decryptMessage(iv: String, ciphertext: String, key: SymmetricKey, conversationID: String, messageID: String,
                        senderUserID: String, senderDeviceID: String, recipientUserID: String, recipientDeviceID: String) throws -> [String: Any] {
        let aad = Self.jsonArray(["serein-message-v1", conversationID, messageID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let clear = try open(iv: iv, ciphertext: ciphertext, key: key, aad: aad)
        guard let value = try JSONSerialization.jsonObject(with: clear) as? [String: Any] else { throw CryptoError.invalidEnvelope }
        return value
    }

    func encryptLayeredMessage(_ content: [String: Any], layer1Key: SymmetricKey, layer2Key: SymmetricKey,
                               conversationID: String, messageID: String, senderUserID: String, senderDeviceID: String,
                               recipientUserID: String, recipientDeviceID: String) throws -> [String: String] {
        let innerAAD = Self.jsonArray(["serein-message-layer1-v2", conversationID, messageID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let inner = try seal(JSONSerialization.data(withJSONObject: content), key: layer1Key, aad: innerAAD)
        let innerObject: [String: Any] = ["version": 1, "algorithm": "AES-256-GCM", "iv": inner["iv"]!, "ciphertext": inner["ciphertext"]!]
        let innerData = try JSONSerialization.data(withJSONObject: innerObject)
        let outerAAD = Self.jsonArray(["serein-message-layer2-v2", conversationID, messageID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let outer = try seal(innerData, key: layer2Key, aad: outerAAD)
        return ["version": "2", "algorithm": "SEREIN-LAYER2-AES-256-GCM", "iv": outer["iv"]!, "ciphertext": outer["ciphertext"]!]
    }

    func decryptLayeredMessage(iv: String, ciphertext: String, layer1Key: SymmetricKey, layer2Key: SymmetricKey, cryptoVersion: Int,
                               conversationID: String, messageID: String, senderUserID: String, senderDeviceID: String,
                               recipientUserID: String, recipientDeviceID: String) throws -> [String: Any] {
        if cryptoVersion == 1 { return try decryptMessage(iv: iv, ciphertext: ciphertext, key: layer1Key, conversationID: conversationID, messageID: messageID, senderUserID: senderUserID, senderDeviceID: senderDeviceID, recipientUserID: recipientUserID, recipientDeviceID: recipientDeviceID) }
        guard cryptoVersion == 2 else { throw CryptoError.invalidEnvelope }
        let outerAAD = Self.jsonArray(["serein-message-layer2-v2", conversationID, messageID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let outerData = try open(iv: iv, ciphertext: ciphertext, key: layer2Key, aad: outerAAD)
        guard let inner = try JSONSerialization.jsonObject(with: outerData) as? [String: Any],
              (inner["version"] as? Int) == 1, inner["algorithm"] as? String == "AES-256-GCM",
              let innerIV = inner["iv"] as? String, let innerCipher = inner["ciphertext"] as? String else { throw CryptoError.invalidEnvelope }
        let innerAAD = Self.jsonArray(["serein-message-layer1-v2", conversationID, messageID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let clear = try open(iv: innerIV, ciphertext: innerCipher, key: layer1Key, aad: innerAAD)
        guard let value = try JSONSerialization.jsonObject(with: clear) as? [String: Any] else { throw CryptoError.invalidEnvelope }
        return value
    }

    func encryptManifest(_ manifest: [String: Any], key: SymmetricKey, transferID: String, senderUserID: String,
                         senderDeviceID: String, recipientUserID: String, recipientDeviceID: String) throws -> [String: String] {
        let aad = Self.jsonArray(["serein-transfer-manifest-v1", transferID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        return try seal(JSONSerialization.data(withJSONObject: manifest), key: key, aad: aad)
    }

    func decryptManifest(iv: String, ciphertext: String, key: SymmetricKey, transferID: String, senderUserID: String,
                         senderDeviceID: String, recipientUserID: String, recipientDeviceID: String) throws -> [String: Any] {
        let aad = Self.jsonArray(["serein-transfer-manifest-v1", transferID, senderUserID, senderDeviceID, recipientUserID, recipientDeviceID])
        let clear = try open(iv: iv, ciphertext: ciphertext, key: key, aad: aad)
        guard let value = try JSONSerialization.jsonObject(with: clear) as? [String: Any] else { throw CryptoError.invalidEnvelope }
        return value
    }

    static func randomKey() -> SymmetricKey { SymmetricKey(size: .bits256) }
    static func randomData(count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { throw NSError(domain: "SereinRandom", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Secure random generation failed."]) }
        return Data(bytes)
    }
    static func key(from data: Data) throws -> SymmetricKey { guard data.count == 32 else { throw CryptoError.invalidKey }; return SymmetricKey(data: data) }

    static func encryptChunk(_ clear: Data, key: SymmetricKey, noncePrefix: Data, index: Int, count: Int,
                             transferID: String, senderUserID: String, senderDeviceID: String, recipientUserID: String) throws -> Data {
        let aad = chunkAAD(transferID: transferID, senderUserID: senderUserID, senderDeviceID: senderDeviceID, recipientUserID: recipientUserID, index: index, count: count)
        let nonce = try chunkNonce(prefix: noncePrefix, index: index)
        let sealed = try AES.GCM.seal(clear, using: key, nonce: nonce, authenticating: aad)
        return sealed.ciphertext + sealed.tag
    }

    static func decryptChunk(_ ciphertext: Data, key: SymmetricKey, noncePrefix: Data, index: Int, count: Int,
                             transferID: String, senderUserID: String, senderDeviceID: String, recipientUserID: String) throws -> Data {
        guard ciphertext.count >= 16 else { throw CryptoError.invalidEnvelope }
        let aad = chunkAAD(transferID: transferID, senderUserID: senderUserID, senderDeviceID: senderDeviceID, recipientUserID: recipientUserID, index: index, count: count)
        let nonce = try chunkNonce(prefix: noncePrefix, index: index)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }

    static func sha256Hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func base64URL(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    static func base64URLDecode(_ value: String) -> Data? {
        let raw = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard raw.range(of: "^[A-Za-z0-9+/]*={0,2}$", options: .regularExpression) != nil else { return nil }
        return Data(base64Encoded: raw + String(repeating: "=", count: (4 - raw.count % 4) % 4))
    }
    static func chunkAAD(transferID: String, senderUserID: String, senderDeviceID: String, recipientUserID: String, index: Int, count: Int) -> Data {
        jsonArray(["serein-transfer-chunk-v1", transferID, senderUserID, senderDeviceID, recipientUserID, index, count])
    }

    private func seal(_ clear: Data, key: SymmetricKey, aad: Data) throws -> [String: String] {
        let nonce = try AES.GCM.Nonce(data: Self.randomData(count: 12))
        let sealed = try AES.GCM.seal(clear, using: key, nonce: nonce, authenticating: aad)
        return ["iv": Data(nonce).base64EncodedString(), "ciphertext": (sealed.ciphertext + sealed.tag).base64EncodedString()]
    }
    private func open(iv: String, ciphertext: String, key: SymmetricKey, aad: Data) throws -> Data {
        guard let nonceData = Data(base64Encoded: iv), nonceData.count == 12,
              let encrypted = Data(base64Encoded: ciphertext), encrypted.count >= 16 else { throw CryptoError.invalidEnvelope }
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encrypted.dropLast(16), tag: encrypted.suffix(16))
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }
    private static func chunkNonce(prefix: Data, index: Int) throws -> AES.GCM.Nonce {
        guard prefix.count == 4, index >= 0, index <= Int(UInt32.max) else { throw CryptoError.invalidEnvelope }
        var number = UInt32(index).bigEndian
        let suffix = withUnsafeBytes(of: &number) { Data($0) }
        return try AES.GCM.Nonce(data: prefix + Data(repeating: 0, count: 4) + suffix)
    }
    private static func jsonArray(_ fields: [Any]) -> Data { (try? JSONSerialization.data(withJSONObject: fields, options: [.fragmentsAllowed])) ?? Data() }

    enum CryptoError: LocalizedError {
        case storedKeyUnavailable, invalidPublicKey, invalidKey, invalidEnvelope
        var errorDescription: String? {
            switch self {
            case .storedKeyUnavailable: return "This device's private key cannot be opened. Re-register this device instead of replacing the key silently."
            case .invalidPublicKey: return "The public device key is malformed."
            case .invalidKey: return "The cryptographic key has an invalid length."
            case .invalidEnvelope: return "The encrypted message or file is malformed or failed authentication."
            }
        }
    }
}

enum SereinKeychain {
    static func read(account: String) throws -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "io.serein.chat.device-keys", kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?; let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw NSError(domain: "SereinKeychain", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Protected device-key storage is unavailable."]) }
        return data
    }
    static func write(_ data: Data, account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "io.serein.chat.device-keys", kSecAttrAccount as String: account]
        let attrs: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemAdd((query.merging(attrs) { _, new in new }) as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let update = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
            guard update == errSecSuccess else { throw NSError(domain: "SereinKeychain", code: Int(update), userInfo: [NSLocalizedDescriptionKey: "Protected device-key storage could not be updated."]) }
        } else if status != errSecSuccess { throw NSError(domain: "SereinKeychain", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Protected device-key storage could not be written."]) }
    }
}
