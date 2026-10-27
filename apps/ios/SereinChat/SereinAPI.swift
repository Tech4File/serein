import Foundation
import CryptoKit
import Combine
import UserNotifications

struct SereinUser: Decodable, Identifiable {
    let id: String
    let username: String
    let email: String
    let display_name: String
    let email_verified: Bool
}
struct SereinDevice: Decodable, Identifiable {
    let id: String
    let name: String
    var created_at: String?
    var last_seen_at: String?
    var current: Bool?
    var online: Bool?
}
struct SereinContact: Decodable, Identifiable {
    var id: String { user_id }
    let user_id: String
    let username: String
    let display_name: String
    let email_verified: Bool
    let online: Bool
    let devices: [SereinDevice]
    let connected_at: String?
    let deleted: Bool?
    let deleted_at: String?
    var isDeleted: Bool { deleted == true }
}
struct SereinContactRequest: Decodable, Identifiable {
    let id: String
    let username: String
    let display_name: String
    let created_at: String
    let direction: String
}
struct SereinBlock: Decodable, Identifiable {
    var id: String { user_id }
    let user_id: String
    let username: String
    let display_name: String
    let created_at: String
}
private struct SereinAccountReply: Decodable { let user: SereinUser; let device: SereinDevice }
private struct SereinAuthReply: Decodable { let account: SereinAccountReply }
private struct SereinVerificationMeta: Decodable { let required: Bool?; let verified: Bool?; let email: String?; let purpose: String? }
private struct SereinErrorReply: Decodable { let error: String; let verification: SereinVerificationMeta?; let retry_after_seconds: Int? }
private struct SereinMessageReply: Decodable { let message: String; let retry_after_seconds: Int? }

private final class SereinNoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private final class SereinNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = SereinNotificationDelegate()
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .badge])
    }
}

@MainActor final class SereinAPI: ObservableObject {
    @Published var verificationRequired = false
    @Published var verificationIdentity = ""
    @Published var verificationEmail = ""
    @Published var verificationPurpose = "email"
    private var pendingLoginIdentity = ""
    private var pendingLoginPassword = ""
    @Published var user: SereinUser?
    @Published var currentDevice: SereinDevice?
    @Published var contacts: [SereinContact] = []
    @Published var contactRequests: [SereinContactRequest] = []
    @Published var blocks: [SereinBlock] = []
    @Published var devices: [SereinDevice] = []
    @Published var presenceVisibility = "contacts"
    @Published var allowContactRequests = true
    @Published var discoverableByEmail = false
    @Published var theme = "system"
    @Published var fontScale = "system"
    @Published var reduceMotion = false
    @Published var notifications = false
    @Published var busy = false
    @Published var startupReady = false
    @Published var errorMessage: String?
    @Published var statusMessage: String?
    @Published var connectionStatus = "Not checked"
    @Published var connectionDetails = ""
    @Published var connectionTestedOrigin = ""
    @Published var apiBase: String {
        didSet { UserDefaults.standard.set(apiBase, forKey: "serein.api-base") }
    }
    private let session: URLSession
    private let defaults = UserDefaults.standard
    var signedIn: Bool { user != nil }

    init() {
        apiBase = UserDefaults.standard.string(forKey: "serein.api-base") ?? "https://api.example.invalid"
        UNUserNotificationCenter.current().delegate = SereinNotificationDelegate.shared
        let config = URLSessionConfiguration.default
        config.httpCookieStorage = HTTPCookieStorage.shared
        config.httpShouldSetCookies = true
        config.httpCookieAcceptPolicy = .always
        let redirectDelegate = SereinNoRedirectDelegate()
        session = URLSession(configuration: config, delegate: redirectDelegate, delegateQueue: nil)
        if defaults.string(forKey: "serein.device-id") == nil {
            defaults.set(UUID().uuidString.lowercased(), forKey: "serein.device-id")
        }
        Task { await restoreSession() }
    }

    private func normalizedServerOrigin(_ value: String) throws -> String {
        guard let components = URLComponents(string: value.trimmingCharacters(in: .whitespacesAndNewlines)),
              components.scheme?.lowercased() == "https", let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil, components.path.isEmpty || components.path == "/",
              components.query == nil, components.fragment == nil else {
            throw NSError(domain: "SereinConnection", code: 1, userInfo: [NSLocalizedDescriptionKey: "Use an HTTPS server origin without a path, credentials, or query values."])
        }
        var origin = "https://\(host)"
        if let port = components.port { origin += ":\(port)" }
        return origin
    }
    func setServerOrigin(_ value: String) throws {
        let normalized = try normalizedServerOrigin(value)
        if apiBase != normalized { cancelVerification() }
        apiBase = normalized
    }
    func testServerConnection(_ value: String) async -> Bool {
        let origin: String
        do { origin = try normalizedServerOrigin(value) }
        catch { connectionTestedOrigin = ""; connectionStatus = "Invalid server URL"; connectionDetails = error.localizedDescription; return false }
        connectionTestedOrigin = ""
        guard let root = URL(string: origin), let url = URL(string: "/healthz", relativeTo: root) else {
            connectionStatus = "Invalid server URL"; connectionDetails = "Enter an HTTPS server origin."; return false
        }
        var config = URLSessionConfiguration.ephemeral; config.httpCookieStorage = nil; config.httpShouldSetCookies = false; config.urlCredentialStorage = nil
        let probeSession = URLSession(configuration: config, delegate: SereinNoRedirectDelegate(), delegateQueue: nil)
        defer { probeSession.finishTasksAndInvalidate() }
        var request = URLRequest(url: url); request.httpMethod = "GET"; request.timeoutInterval = 10; request.cachePolicy = .reloadIgnoringLocalCacheData; request.setValue("application/json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await probeSession.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 || http.statusCode == 503,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let healthStatus = object["status"] as? String, ["ready", "degraded"].contains(healthStatus),
                  let raw = object["components"] as? [String: Any] else {
                connectionStatus = "Could not confirm server health"; connectionDetails = "The server returned an unexpected health response."; return false
            }
            func safe(_ key: String) -> String { let value = raw[key] as? String ?? "unknown"; return ["ready", "ok", "available", "unavailable", "degraded", "disabled", "configured", "not_configured", "unknown"].contains(value) ? value : "unknown" }
            let ready = healthStatus == "ready" && http.statusCode == 200
                connectionTestedOrigin = origin
            connectionStatus = ready ? "Connected · ready" : "Reachable · degraded"
            connectionDetails = "API: \(safe("api")) · Database: \(safe("database")) · Web: \(safe("frontend")) · Email: \(safe("email_delivery"))"
            return true
        } catch {
            connectionStatus = "Not connected"; connectionDetails = "Could not reach the server over HTTPS."; return false
        }
    }
    func signIn(identity: String, password: String) async {
        let normalizedIdentity = identity.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        pendingLoginIdentity = normalizedIdentity
        pendingLoginPassword = password
        verificationPurpose = "login"
        await authenticate(path: "/api/v1/auth/login", values: ["identity": normalizedIdentity, "password": password])
    }
    func register(username: String, email: String, displayName: String, password: String) async {
        busy = true; errorMessage = nil; statusMessage = nil
        defer { busy = false }
        let cleanEmail = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        do {
            _ = try await request("/api/v1/auth/register", method: "POST", values: [
                "username": username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                "email": cleanEmail,
                "display_name": displayName.trimmingCharacters(in: .whitespacesAndNewlines),
                "password": password
            ])
            verificationRequired = true; verificationIdentity = cleanEmail; verificationEmail = cleanEmail; verificationPurpose = "email"
            pendingLoginIdentity = ""; pendingLoginPassword = ""
            statusMessage = "Check your email for a six-digit verification code."
        } catch {
            let ns = error as NSError
            if ns.userInfo["verificationRequired"] as? Bool == true,
               let address = ns.userInfo["verificationEmail"] as? String {
                verificationRequired = true; verificationEmail = address; verificationIdentity = address; verificationPurpose = "email"
                pendingLoginIdentity = ""; pendingLoginPassword = ""
            }
            errorMessage = error.localizedDescription
        }
    }
    func verifyEmail(code: String, email: String) async {
        busy = true; errorMessage = nil; statusMessage = nil
        defer { busy = false }
        do {
            let loginOtp = verificationPurpose == "login"
            let path = loginOtp ? "/api/v1/auth/verify-login" : "/api/v1/auth/verify-email"
            let values: [String: Any] = loginOtp
                ? ["identity": pendingLoginIdentity, "password": pendingLoginPassword, "code": code, "device_name": "Serein iOS", "device_id": deviceID]
                : ["email": email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), "code": code, "device_name": "Serein iOS", "device_id": deviceID]
            let data = try await request(path, method: "POST", values: values)
            let reply = try JSONDecoder().decode(SereinAuthReply.self, from: data)
            user = reply.account.user; currentDevice = reply.account.device
            defaults.set(reply.account.device.id, forKey: "serein.device-id")
            cancelVerification()
            await refreshAccountData()
        } catch { errorMessage = error.localizedDescription }
    }
    func cancelVerification() {
        verificationRequired = false; verificationIdentity = ""; verificationEmail = ""; verificationPurpose = "email"
        pendingLoginIdentity = ""; pendingLoginPassword = ""
    }
    func resendVerification(identity: String) async -> Int? {
        busy = true; errorMessage = nil; statusMessage = nil
        defer { busy = false }
        do {
            let data = try await request("/api/v1/auth/resend-verification", method: "POST", values: ["identity": identity.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()])
            let reply = try JSONDecoder().decode(SereinMessageReply.self, from: data)
            statusMessage = reply.message; return reply.retry_after_seconds ?? 60
        } catch {
            let ns = error as NSError; errorMessage = error.localizedDescription
            return ns.userInfo["retryAfterSeconds"] as? Int
        }
    }
    private var deviceID: String { defaults.string(forKey: "serein.device-id") ?? UUID().uuidString.lowercased() }
    var backupDeviceID: String { deviceID }

    private func authenticate(path: String, values: [String: Any]) async {
        busy = true; errorMessage = nil; statusMessage = nil
        defer { busy = false }
        do {
            let data = try await request(path, method: "POST", values: values)
            let reply = try JSONDecoder().decode(SereinAuthReply.self, from: data)
            user = reply.account.user; currentDevice = reply.account.device
            defaults.set(reply.account.device.id, forKey: "serein.device-id")
            if path == "/api/v1/auth/login" { pendingLoginIdentity = ""; pendingLoginPassword = "" }
            await refreshAccountData()
        } catch {
            let ns = error as NSError
            if path == "/api/v1/auth/login", ns.userInfo["verificationRequired"] as? Bool == true {
                let address = (ns.userInfo["verificationEmail"] as? String ?? "").lowercased()
                verificationRequired = true; verificationEmail = address
                verificationPurpose = (ns.userInfo["verificationPurpose"] as? String) == "login" ? "login" : "email"
                verificationIdentity = verificationPurpose == "login" ? pendingLoginIdentity : address
                errorMessage = error.localizedDescription
            } else { errorMessage = error.localizedDescription }
        }
    }
    func restoreSession() async {
        defer { startupReady = true }
        do {
            let data = try await request("/api/v1/me")
            let reply = try JSONDecoder().decode(SereinAccountReply.self, from: data)
            user = reply.user; currentDevice = reply.device
            defaults.set(reply.device.id, forKey: "serein.device-id")
            await refreshAccountData()
        } catch { /* No stored API session: show sign-in. */ }
    }
    func refreshAccountData() async {
        async let contactsData = request("/api/v1/contacts")
        async let requestsData = request("/api/v1/contact-requests")
        async let blocksData = request("/api/v1/blocks")
        async let devicesData = request("/api/v1/devices")
        async let settingsData = request("/api/v1/settings")
        do {
            let (c, r, b, d, s) = try await (contactsData, requestsData, blocksData, devicesData, settingsData)
            contacts = try JSONDecoder().decode([SereinContact].self, from: c)
            contactRequests = try JSONDecoder().decode([SereinContactRequest].self, from: r)
            blocks = try JSONDecoder().decode([SereinBlock].self, from: b)
            devices = try JSONDecoder().decode([SereinDevice].self, from: d)
            let prefs = try JSONSerialization.jsonObject(with: s) as? [String: Any] ?? [:]
            theme = ["system", "light", "dark"].contains(prefs["theme"] as? String ?? "") ? (prefs["theme"] as? String ?? "system") : "system"
            let savedScale = prefs["font_scale"] as? String ?? "system"
            fontScale = ["system", "standard", "large", "extra_large"].contains(savedScale) ? (savedScale == "standard" ? "system" : savedScale) : "system"
            reduceMotion = prefs["reduce_motion"] as? Bool ?? false
            notifications = prefs["notifications"] as? Bool ?? false
            defaults.set(notifications, forKey: "serein.notifications.enabled")
            presenceVisibility = (prefs["presence_visibility"] as? String) == "nobody" ? "nobody" : "contacts"
            allowContactRequests = prefs["allow_contact_requests"] as? Bool ?? true
            discoverableByEmail = prefs["discoverable_by_email"] as? Bool ?? false
            errorMessage = nil
        } catch { errorMessage = error.localizedDescription }
    }
    func contactsData() async throws -> Data { try await request("/api/v1/contacts") }
    func requestBackupKey(accountID: String) async throws -> Data {
        guard let accountUUID = UUID(uuidString: accountID), let deviceUUID = UUID(uuidString: deviceID) else {
            throw NSError(domain: "SereinBackupKey", code: 1, userInfo: [NSLocalizedDescriptionKey: "Signed-in account or device identity is unavailable."])
        }
        let account = accountUUID.uuidString.lowercased(), device = deviceUUID.uuidString.lowercased()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let point = ephemeral.publicKey.x963Representation
        guard point.count == 65, point.first == 4 else { throw NSError(domain: "SereinBackupKey", code: 2, userInfo: [NSLocalizedDescriptionKey: "Could not prepare a one-use backup key request."]) }
        let clientX = base64URL(Data(point[1..<33])), clientY = base64URL(Data(point[33..<65]))
        let clientJWK: [String: String] = ["kty": "EC", "crv": "P-256", "x": clientX, "y": clientY]
        let response = try await request("/api/v1/backups/key-envelope", method: "POST", values: ["client_public_key": clientJWK])
        guard let envelope = try JSONSerialization.jsonObject(with: response) as? [String: Any],
              envelope["key_version"] as? Int == 1,
              let server = envelope["server_public_key"] as? [String: String],
              server["kty"] == "EC", server["crv"] == "P-256",
              let sxText = server["x"], let syText = server["y"],
              let sx = decodeBackupBase64URL(sxText), sx.count == 32,
              let sy = decodeBackupBase64URL(syText), sy.count == 32,
              let saltText = envelope["salt"] as? String, let salt = decodeBackupBase64URL(saltText), salt.count == 32,
              let nonceText = envelope["nonce"] as? String, let nonce = decodeBackupBase64URL(nonceText), nonce.count == 12,
              let ciphertextText = envelope["ciphertext"] as? String, let ciphertext = decodeBackupBase64URL(ciphertextText), ciphertext.count == 48 else {
            throw NSError(domain: "SereinBackupKey", code: 3, userInfo: [NSLocalizedDescriptionKey: "The server backup key envelope is malformed."])
        }
        var serverPoint = Data([4]); serverPoint.append(sx); serverPoint.append(sy)
        let serverPublic = try P256.KeyAgreement.PublicKey(x963Representation: serverPoint)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: serverPublic)
        let info = try JSONSerialization.data(withJSONObject: ["serein-backup-key-envelope-kdf-v1", account, device, 1, clientX, clientY, sxText, syText] as [Any], options: [.fragmentsAllowed])
        let aad = try JSONSerialization.data(withJSONObject: ["serein-backup-key-envelope-aad-v1", account, device, 1, clientX, clientY, sxText, syText, saltText, nonceText] as [Any], options: [.fragmentsAllowed])
        let wrappingKey = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: Data(ciphertext.prefix(32)), tag: Data(ciphertext.suffix(16)))
        let clear = try AES.GCM.open(box, using: wrappingKey, authenticating: aad)
        guard clear.count == 32 else { throw NSError(domain: "SereinBackupKey", code: 4, userInfo: [NSLocalizedDescriptionKey: "The server backup key envelope contained an invalid key."]) }
        return clear
    }
    private func base64URL(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    private func decodeBackupBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty, value.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: standard + String(repeating: "=", count: (4 - standard.count % 4) % 4))
    }
    func registerDeviceKey(_ publicJWK: [String: String], layer2PublicJWK: [String: String], ratchetVersion: Int) async throws -> [String: Any] {
        guard ratchetVersion == 2 || ratchetVersion == 3 else { throw APIError.invalidResponse }
        let data = try await request("/api/v1/device-key", method: "PUT", values: ["algorithm": "ECDH-P256", "public_key": publicJWK, "layer2_public_key": layer2PublicJWK, "ratchet_version": ratchetVersion])
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
    func contactDeviceKeys(_ contactID: String) async throws -> [String: Any] {
        let data = try await request("/api/v1/contacts/\(contactID)/device-keys")
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
    func messageHistory(afterCreatedAt: String? = nil, afterID: String? = nil) async throws -> Data {
        var components = URLComponents(); components.path = "/api/v1/messages"
        var items = [URLQueryItem(name: "limit", value: "100")]
        if let afterCreatedAt, let afterID { items.append(URLQueryItem(name: "after_created_at", value: afterCreatedAt)); items.append(URLQueryItem(name: "after_id", value: afterID)) }
        components.queryItems = items
        return try await request(components.string ?? "/api/v1/messages?limit=100")
    }
    func acknowledgeMessage(_ id: String) async throws { _ = try await request("/api/v1/messages/\(id)/ack", method: "POST", values: [:]) }
    func markMessageRead(_ id: String) async throws { _ = try await request("/api/v1/messages/\(id)/read", method: "POST", values: [:]) }
    func markMessagesRead(_ ids: [String]) async throws { guard !ids.isEmpty else { return }; _ = try await request("/api/v1/messages/read", method: "POST", values: ["ids": ids]) }
    func messageReceipts(ids: [String]) async throws -> Data { try await request("/api/v1/messages/receipts", method: "POST", values: ["ids": ids]) }
    func sendEncryptedEnvelope(id: String, to deviceID: String, iv: String, ciphertext: String, cryptoVersion: Int) async throws {
        _ = try await request("/api/v1/messages", method: "POST", values: ["id": id, "to": deviceID, "crypto_version": cryptoVersion, "iv": iv, "ciphertext": ciphertext])
    }
    func transfersData() async throws -> Data { try await request("/api/v1/transfers") }
    func createTransfer(_ values: [String: Any]) async throws { _ = try await request("/api/v1/transfers", method: "POST", values: values) }
    func acknowledgeTransfer(_ id: String) async throws { _ = try await request("/api/v1/transfers/\(id)/ack", method: "POST", values: [:]) }
    func abortTransfer(_ id: String) async throws { _ = try await request("/api/v1/transfers/\(id)", method: "DELETE") }
    func uploadTransferChunk(_ id: String, index: Int, ciphertext: Data, digest: String) async throws {
        _ = try await transferRequest("/api/v1/transfers/\(id)/chunks/\(index)", method: "PUT", body: ciphertext, headers: ["Content-Type": "application/octet-stream", "X-Chunk-SHA256": digest])
    }
    func downloadTransferChunk(_ id: String, index: Int) async throws -> (Data, String) {
        let (data, response) = try await transferRequest("/api/v1/transfers/\(id)/chunks/\(index)", method: "GET", body: nil, headers: ["Accept": "application/octet-stream"])
        guard let digest = response.value(forHTTPHeaderField: "X-Chunk-SHA256"), digest.count == 64 else { throw URLError(.cannotDecodeContentData) }
        return (data, digest.lowercased())
    }
    private func transferRequest(_ path: String, method: String, body: Data?, headers: [String: String]) async throws -> (Data, HTTPURLResponse) {
        let base = apiBase.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let root = URL(string: base), root.scheme?.lowercased() == "https", root.host != nil, root.user == nil, root.password == nil, root.query == nil, root.fragment == nil,
              let url = URL(string: path, relativeTo: root) else { throw URLError(.badURL) }
        var request = URLRequest(url: url); request.httpMethod = method; request.timeoutInterval = 40
        request.cachePolicy = .reloadIgnoringLocalCacheData
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        request.httpBody = body
        let (stream, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        let maximum = 512 * 1024
        if let length = http.value(forHTTPHeaderField: "Content-Length"), let declared = Int(length), declared > maximum {
            throw NSError(domain: "SereinTransfer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Transfer chunk exceeded its response size limit."])
        }
        var data = Data()
        if let length = http.value(forHTTPHeaderField: "Content-Length"), let declared = Int(length), declared > 0 { data.reserveCapacity(min(declared, maximum)) }
        for try await byte in stream {
            guard data.count < maximum else { throw NSError(domain: "SereinTransfer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Transfer chunk exceeded its response size limit."]) }
            data.append(byte)
        }
        guard (200..<300).contains(http.statusCode) else {
            let reply = try? JSONDecoder().decode(SereinErrorReply.self, from: data)
            throw NSError(domain: "SereinTransfer", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: reply?.error ?? "Transfer request failed (\(http.statusCode))."])
        }
        return (data, http)
    }
    func addContact(identity: String) async {
        do { let data = try await request("/api/v1/contact-requests", method: "POST", values: ["identity": identity]); let reply = try JSONDecoder().decode(SereinMessageReply.self, from: data); errorMessage = reply.message; await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func acceptContactRequest(_ request: SereinContactRequest) async {
        do { _ = try await self.request("/api/v1/contact-requests/\(request.id)/accept", method: "POST", values: [:]); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func dismissContactRequest(_ request: SereinContactRequest) async {
        do { _ = try await self.request("/api/v1/contact-requests/\(request.id)", method: "DELETE"); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func block(_ contact: SereinContact) async {
        do { _ = try await request("/api/v1/blocks/\(contact.user_id)", method: "PUT", values: [:]); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func unblock(_ blocked: SereinBlock) async {
        do { _ = try await request("/api/v1/blocks/\(blocked.user_id)", method: "DELETE"); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func removeContact(_ contact: SereinContact) async {
        do { _ = try await request("/api/v1/contacts/\(contact.user_id)", method: "DELETE"); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func deleteAccount(password: String) async -> (deleted: Bool, localDataCleared: Bool, error: String?) {
        guard let user else { return (false, false, "Sign in again before deleting the account.") }
        do {
            _ = try await request("/api/v1/me", method: "DELETE", values: ["password": password])
            var cleared = true
            do { try SereinLocalStore.delete(accountID: user.id) } catch { cleared = false }
            do { try SereinDeviceCrypto.deleteAccountKeys(userID: user.id) } catch { cleared = false }
            if !SereinAttachmentStore.shared.deleteForAccount(user.id) { cleared = false }
            if let root = URL(string: apiBase), let cookies = HTTPCookieStorage.shared.cookies(for: root) { cookies.filter { $0.name == "serein_session" }.forEach { HTTPCookieStorage.shared.deleteCookie($0) } }
            defaults.removeObject(forKey: "serein.device-id")
            self.user = nil; currentDevice = nil; contacts = []; contactRequests = []; blocks = []; devices = []
            cancelVerification()
            return (true, cleared, nil)
        } catch { return (false, false, error.localizedDescription) }
    }
    func setNotificationsEnabled(_ enabled: Bool) async -> Bool {
        let center = UNUserNotificationCenter.current()
        var allowed = false
        if enabled {
            let current = await center.notificationSettings()
            switch current.authorizationStatus {
            case .notDetermined:
                do { allowed = try await center.requestAuthorization(options: [.alert, .sound, .badge]) }
                catch { errorMessage = error.localizedDescription }
            case .authorized, .provisional, .ephemeral: allowed = true
            case .denied: allowed = false
            @unknown default: allowed = false
            }
        }
        notifications = enabled && allowed
        defaults.set(notifications, forKey: "serein.notifications.enabled")
        await savePreferences()
        return notifications == enabled
    }
    func notificationAuthorizationStatus() async -> UNAuthorizationStatus {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        return settings.authorizationStatus
    }
    func notifyIncomingMessage() {
        guard notifications, defaults.bool(forKey: "serein.notifications.enabled") else { return }
        let center = UNUserNotificationCenter.current()
        let content = UNMutableNotificationContent()
        content.title = "New encrypted message"
        content.body = "You have a new encrypted message in Serein."
        content.sound = defaults.object(forKey: "serein.notifications.sound") as? Bool == false ? nil : .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false))
        center.add(request) { _ in }
    }
    func savePreferences() async {
        defaults.set(notifications, forKey: "serein.notifications.enabled")
        do {
            _ = try await request("/api/v1/settings", method: "PUT", values: ["theme": theme, "font_scale": fontScale, "reduce_motion": reduceMotion, "notifications": notifications, "presence_visibility": presenceVisibility, "allow_contact_requests": allowContactRequests, "discoverable_by_email": discoverableByEmail])
        } catch { errorMessage = error.localizedDescription }
    }
    func revoke(_ device: SereinDevice) async {
        do { _ = try await request("/api/v1/devices/\(device.id)", method: "DELETE"); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func revokeOthers() async {
        do { _ = try await request("/api/v1/devices/revoke-others", method: "POST", values: [:]); await refreshAccountData() }
        catch { errorMessage = error.localizedDescription }
    }
    func signOut() async -> Bool {
        var serverRevoked = false
        do { _ = try await request("/api/v1/auth/logout", method: "POST", values: [:]); serverRevoked = true }
        catch { errorMessage = error.localizedDescription }
        if let root = URL(string: apiBase), let cookies = HTTPCookieStorage.shared.cookies(for: root) {
            cookies.filter { $0.name == "serein_session" }.forEach { HTTPCookieStorage.shared.deleteCookie($0) }
        }
        user = nil; currentDevice = nil; contacts = []; contactRequests = []; blocks = []; devices = []
        cancelVerification()
        return serverRevoked
    }
    private func request(_ path: String, method: String = "GET", values: [String: Any]? = nil) async throws -> Data {
        let base = apiBase.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let root = URL(string: base), root.scheme?.lowercased() == "https", root.host != nil, root.user == nil, root.password == nil, root.query == nil, root.fragment == nil, let url = URL(string: path, relativeTo: root) else {
            throw NSError(domain: "SereinAPI", code: 1, userInfo: [NSLocalizedDescriptionKey: "Enter a valid HTTPS API URL."])
        }
        var request = URLRequest(url: url); request.httpMethod = method
        request.timeoutInterval = 20; request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let values { request.setValue("application/json", forHTTPHeaderField: "Content-Type"); request.httpBody = try JSONSerialization.data(withJSONObject: values) }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401, let cookies = HTTPCookieStorage.shared.cookies(for: root) { cookies.filter { $0.name == "serein_session" }.forEach { HTTPCookieStorage.shared.deleteCookie($0) } }
            let reply = try? JSONDecoder().decode(SereinErrorReply.self, from: data)
            let detail = reply?.error ?? "API request failed (\(http.statusCode))."
            var info: [String: Any] = [NSLocalizedDescriptionKey: detail]
            if reply?.verification?.required == true {
                info["verificationRequired"] = true
                info["verificationEmail"] = reply?.verification?.email ?? ""
                info["verificationPurpose"] = reply?.verification?.purpose ?? "email"
            }
            if let retry = reply?.retry_after_seconds { info["retryAfterSeconds"] = retry }
            throw NSError(domain: "SereinAPI", code: http.statusCode, userInfo: info)
        }
        return data
    }
}
