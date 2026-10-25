import Compression
import CryptoKit
import Foundation

/// Portable, bounded `.srbk` container compatible with the web/Android v2 format.
enum SereinBackupStore {
    static let mimeType = "application/vnd.serein.backup"
    static let format = "SEREIN-BACKUP"
    static let maximumBytes = 64 * 1024 * 1024
    static let maximumMessages = 100_000
    private static let magic = Data("SEREINBK".utf8)
    private static let maximumHeaderBytes = 16 * 1024
    private static let legacyIterations = 600_000
    private static let v2KDF = "HKDF-SHA256-ACCOUNT-UUID"
    private static let v1KDF = "PBKDF2-HMAC-SHA256"

    struct Info {
        let version: Int
        let createdAt: String
        let snapshotID: String
    }

    private struct Parsed {
        let header: [String: Any]
        let ciphertext: Data
        let info: Info
    }

    static func create(accountID: String, username: String, snapshot: [String: Any]) throws -> (bytes: Data, filename: String) {
        let id = try canonicalAccountID(accountID)
        let createdAt = ISO8601DateFormatter().string(from: Date())
        let snapshotID = UUID().uuidString.lowercased()
        let payload: [String: Any] = [
            "format": format, "version": 2,
            "owner": ["accountId": id, "username": username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()],
            "created_at": createdAt, "snapshot_id": snapshotID, "data": snapshot,
        ]
        let clear = try JSONSerialization.data(withJSONObject: payload, options: [.fragmentsAllowed])
        guard clear.count <= maximumBytes else { throw BackupError.tooLarge }
        let nonceData = try SereinDeviceCrypto.randomData(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let nonceText = base64URL(nonceData)
        let header: [String: Any] = [
            "format": format, "version": 2, "kdf": v2KDF, "key_derivation_version": 1,
            "snapshot_id": snapshotID, "created_at": createdAt, "compression": "none", "payload_iv": nonceText,
        ]
        let aad = try v2AAD(accountID: id, header: header)
        let key = accountKey(id)
        let sealed = try AES.GCM.seal(clear, using: key, nonce: nonce, authenticating: aad)
        var ciphertext = sealed.ciphertext
        ciphertext.append(sealed.tag)
        let bytes = try pack(header: header, ciphertext: ciphertext)
        let stamp = createdAt.replacingOccurrences(of: ":", with: "-").replacingOccurrences(of: ".", with: "-")
        return (bytes, "serein-backup-\(stamp)-\(snapshotID.prefix(8)).srbk")
    }

    static func inspect(_ file: Data) throws -> Info { try unpack(file).info }

    static func open(accountID: String, username: String, legacyPassword: String = "", file: Data) throws -> (data: [String: Any], info: Info) {
        let id = try canonicalAccountID(accountID)
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parsed = try unpack(file)
        if parsed.info.version == 2 { return (try openV2(id: id, parsed: parsed), parsed.info) }
        if parsed.info.version == 1 { return (try openV1(id: id, username: user, password: legacyPassword, parsed: parsed), parsed.info) }
        throw BackupError.unsupportedVersion
    }

    private static func openV2(id: String, parsed: Parsed) throws -> [String: Any] {
        guard parsed.header["kdf"] as? String == v2KDF,
              parsed.header["key_derivation_version"] as? Int == 1,
              let nonceText = parsed.header["payload_iv"] as? String,
              let nonceData = decodeBase64URL(nonceText), nonceData.count == 12,
              let compression = parsed.header["compression"] as? String else { throw BackupError.malformed }
        let aad = try v2AAD(accountID: id, header: parsed.header)
        let (encrypted, tag) = try splitCiphertext(parsed.ciphertext)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData), ciphertext: encrypted, tag: tag)
        var clear = try AES.GCM.open(box, using: accountKey(id), authenticating: aad)
        if clear.count > maximumBytes { throw BackupError.tooLarge }
        if compression == "deflate" { clear = try decompress(clear) }
        else if compression != "none" { throw BackupError.malformed }
        return try validatePayload(clear, accountID: id, header: parsed.header)
    }

    private static func openV1(id: String, username: String, password: String, parsed: Parsed) throws -> [String: Any] {
        let h = parsed.header
        guard h["kdf"] as? String == v1KDF, h["iterations"] as? Int == legacyIterations,
              let saltText = h["salt"] as? String, let salt = decodeBase64URL(saltText), salt.count == 16,
              let wrapText = h["key_wrap_iv"] as? String, let wrapNonceData = decodeBase64URL(wrapText), wrapNonceData.count == 12,
              let wrappedText = h["wrapped_key"] as? String, let wrapped = decodeBase64URL(wrappedText), wrapped.count == 48,
              let payloadText = h["payload_iv"] as? String, let payloadNonceData = decodeBase64URL(payloadText), payloadNonceData.count == 12,
              !password.isEmpty, password.utf8.count <= 1024 else { throw BackupError.legacyPasswordRequired }
        let passKey = pbkdf2(password: Data(password.utf8), salt: salt, iterations: legacyIterations)
        let wrapAAD = try v1WrapAAD(id: id, username: username, header: h)
        let (wrappedCipher, wrappedTag) = try splitCiphertext(wrapped)
        let wrappedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: wrapNonceData), ciphertext: wrappedCipher, tag: wrappedTag)
        let dataKeyData = try AES.GCM.open(wrappedBox, using: passKey, authenticating: wrapAAD)
        guard dataKeyData.count == 32 else { throw BackupError.malformed }
        let payloadAAD = try v1PayloadAAD(id: id, username: username, header: h)
        let (encrypted, tag) = try splitCiphertext(parsed.ciphertext)
        let payloadBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: payloadNonceData), ciphertext: encrypted, tag: tag)
        var clear = try AES.GCM.open(payloadBox, using: SymmetricKey(data: dataKeyData), authenticating: payloadAAD)
        if clear.count > maximumBytes { throw BackupError.tooLarge }
        if h["compression"] as? String == "deflate" { clear = try decompress(clear) }
        else if h["compression"] as? String != "none" { throw BackupError.malformed }
        return try validatePayload(clear, accountID: id, header: h, legacyUsername: username)
    }

    private static func validatePayload(_ bytes: Data, accountID: String, header: [String: Any], legacyUsername: String? = nil) throws -> [String: Any] {
        guard bytes.count <= maximumBytes,
              let payload = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let expectedVersion = header["version"] as? Int,
              let expectedSnapshot = header["snapshot_id"] as? String,
              let expectedCreated = header["created_at"] as? String,
              let owner = payload["owner"] as? [String: Any],
              let ownerID = owner["accountId"] as? String,
              let data = payload["data"] as? [String: Any],
              payload["format"] as? String == format,
              payload["version"] as? Int == expectedVersion,
              payload["snapshot_id"] as? String == expectedSnapshot,
              payload["created_at"] as? String == expectedCreated,
              ownerID == accountID,
              legacyUsername == nil || (owner["username"] as? String) == legacyUsername else { throw BackupError.accountOrContentsInvalid }
        return data
    }

    private static func accountKey(_ id: String) -> SymmetricKey {
        SymmetricKey(data: Data(id.utf8)).hkdfDerivedKey(
            using: SHA256.self,
            salt: Data("Serein backup account key v2".utf8),
            sharedInfo: Data("Serein backup stable key v1".utf8),
            outputByteCount: 32
        )
    }

    private static func v2AAD(accountID: String, header: [String: Any]) throws -> Data {
        guard let snapshot = header["snapshot_id"] as? String, let created = header["created_at"] as? String,
              let compression = header["compression"] as? String, let kdf = header["kdf"] as? String,
              let derivation = header["key_derivation_version"] as? Int, let iv = header["payload_iv"] as? String else { throw BackupError.malformed }
        return try JSONSerialization.data(withJSONObject: ["serein-backup-payload-v2", format, 2, accountID, snapshot, created, compression, kdf, derivation, iv], options: [.fragmentsAllowed])
    }

    private static func v1WrapAAD(id: String, username: String, header: [String: Any]) throws -> Data {
        guard let snapshot = header["snapshot_id"] as? String, let kdf = header["kdf"] as? String,
              let iterations = header["iterations"] as? Int, let salt = header["salt"] as? String else { throw BackupError.malformed }
        return try JSONSerialization.data(withJSONObject: ["serein-backup-key-wrap-v1", format, 1, id, username, snapshot, kdf, iterations, salt], options: [.fragmentsAllowed])
    }

    private static func v1PayloadAAD(id: String, username: String, header: [String: Any]) throws -> Data {
        guard let snapshot = header["snapshot_id"] as? String, let created = header["created_at"] as? String,
              let compression = header["compression"] as? String, let kdf = header["kdf"] as? String,
              let iterations = header["iterations"] as? Int, let salt = header["salt"] as? String,
              let wrapIV = header["key_wrap_iv"] as? String, let wrapped = header["wrapped_key"] as? String,
              let payloadIV = header["payload_iv"] as? String else { throw BackupError.malformed }
        return try JSONSerialization.data(withJSONObject: ["serein-backup-payload-v1", format, 1, id, username, snapshot, created, compression, kdf, iterations, salt, wrapIV, wrapped, payloadIV], options: [.fragmentsAllowed])
    }

    private static func pbkdf2(password: Data, salt: Data, iterations: Int) -> SymmetricKey {
        let passwordKey = SymmetricKey(data: password)
        var first = salt; first.append(contentsOf: [0, 0, 0, 1])
        var u = Data(HMAC<SHA256>.authenticationCode(for: first, using: passwordKey))
        var result = u
        if iterations > 1 {
            for _ in 1..<iterations {
                u = Data(HMAC<SHA256>.authenticationCode(for: u, using: passwordKey))
                for index in result.indices { result[index] ^= u[index] }
            }
        }
        return SymmetricKey(data: result)
    }

    private static func pack(header: [String: Any], ciphertext: Data) throws -> Data {
        let encoded = try JSONSerialization.data(withJSONObject: header, options: [.fragmentsAllowed])
        guard encoded.count <= maximumHeaderBytes, ciphertext.count <= maximumBytes else { throw BackupError.tooLarge }
        var output = magic
        var length = UInt32(encoded.count).bigEndian
        withUnsafeBytes(of: &length) { output.append(contentsOf: $0) }
        output.append(encoded); output.append(ciphertext)
        guard output.count <= maximumBytes else { throw BackupError.tooLarge }
        return output
    }

    private static func unpack(_ file: Data) throws -> Parsed {
        guard file.count >= 8 + 4 + 2 + 16, file.count <= maximumBytes, file.prefix(8) == magic else { throw BackupError.malformed }
        let bytes = [UInt8](file.prefix(12))
        let headerLength = (Int(bytes[8]) << 24) | (Int(bytes[9]) << 16) | (Int(bytes[10]) << 8) | Int(bytes[11])
        let start = 12, end = start + headerLength
        guard headerLength >= 2, headerLength <= maximumHeaderBytes, end < file.count, file.count - end >= 16,
              let header = try JSONSerialization.jsonObject(with: file.subdata(in: start..<end)) as? [String: Any],
              header["format"] as? String == format,
              let version = header["version"] as? Int,
              let snapshot = header["snapshot_id"] as? String, UUID(uuidString: snapshot) != nil,
              let created = header["created_at"] as? String, isValidTimestamp(created),
              ["none", "deflate"].contains(header["compression"] as? String ?? "") else { throw BackupError.malformed }
        let expectedV2: Set<String> = ["format", "version", "kdf", "key_derivation_version", "snapshot_id", "created_at", "compression", "payload_iv"]
        let expectedV1: Set<String> = ["format", "version", "kdf", "iterations", "salt", "snapshot_id", "created_at", "compression", "key_wrap_iv", "wrapped_key", "payload_iv"]
        let expected = version == 2 ? expectedV2 : expectedV1
        guard (version == 1 || version == 2), Set(header.keys) == expected,
              let ivText = header["payload_iv"] as? String, let iv = decodeBase64URL(ivText), iv.count == 12 else { throw BackupError.malformed }
        if version == 2 {
            guard header["kdf"] as? String == v2KDF, header["key_derivation_version"] as? Int == 1 else { throw BackupError.unsupportedKDF }
        } else {
            guard header["kdf"] as? String == v1KDF, header["iterations"] as? Int == legacyIterations,
                  let salt = decodeBase64URL(header["salt"] as? String ?? ""), salt.count == 16,
                  let wrapIV = decodeBase64URL(header["key_wrap_iv"] as? String ?? ""), wrapIV.count == 12,
                  let wrapped = decodeBase64URL(header["wrapped_key"] as? String ?? ""), wrapped.count == 48 else { throw BackupError.malformed }
        }
        return Parsed(header: header, ciphertext: file.subdata(in: end..<file.count), info: Info(version: version, createdAt: created, snapshotID: snapshot))
    }

    private static func splitCiphertext(_ combined: Data) throws -> (Data, Data) {
        guard combined.count >= 16 else { throw BackupError.malformed }
        return (combined.prefix(combined.count - 16), combined.suffix(16))
    }

    private static func decompress(_ input: Data) throws -> Data {
        guard !input.isEmpty else { return Data() }
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: maximumBytes)
        defer { buffer.deallocate() }
        let count = input.withUnsafeBytes { raw -> Int in
            guard let source = raw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return compression_decode_buffer(buffer, maximumBytes, source, input.count, nil, COMPRESSION_ZLIB)
        }
        guard count > 0, count <= maximumBytes else { throw BackupError.tooLarge }
        return Data(bytes: buffer, count: count)
    }

    private static func isValidTimestamp(_ value: String) -> Bool {
        let formatter = ISO8601DateFormatter()
        if formatter.date(from: value) != nil { return true }
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) != nil
    }

    private static func canonicalAccountID(_ value: String) throws -> String {
        guard let uuid = UUID(uuidString: value), value.lowercased() == uuid.uuidString.lowercased(),
              value.lowercased().range(of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#, options: .regularExpression) != nil else { throw BackupError.identityUnavailable }
        return uuid.uuidString.lowercased()
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty, value.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: standard + String(repeating: "=", count: (4 - standard.count % 4) % 4))
    }

    enum BackupError: LocalizedError {
        case identityUnavailable, malformed, unsupportedVersion, unsupportedKDF, legacyPasswordRequired, accountOrContentsInvalid, tooLarge
        var errorDescription: String? {
            switch self {
            case .identityUnavailable: return "Backup account identity is unavailable."
            case .malformed: return "The selected Serein backup is malformed or damaged."
            case .unsupportedVersion: return "This Serein backup version is not supported."
            case .unsupportedKDF: return "This backup uses unsupported key-derivation parameters."
            case .legacyPasswordRequired: return "Enter the original password for this legacy backup."
            case .accountOrContentsInvalid: return "Backup could not be opened for this account or its contents are damaged."
            case .tooLarge: return "This backup exceeds the 64 MiB iOS safety limit."
            }
        }
    }
}
