import Foundation
import Combine

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
private struct SereinErrorReply: Decodable { let error: String }
private struct SereinMessageReply: Decodable { let message: String }

private final class SereinNoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

@MainActor final class SereinAPI: ObservableObject {
    @Published var verificationRequired = false
    @Published var verificationIdentity = ""
    @Published var verificationEmail = ""
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
    @Published var fontScale = "standard"
    @Published var reduceMotion = false
    @Published var notifications = false
    @Published var busy = false
    @Published var errorMessage: String?
    @Published var apiBase: String {
        didSet { UserDefaults.standard.set(apiBase, forKey: "serein.api-base") }
    }
    private let session: URLSession
    private let defaults = UserDefaults.standard
    var signedIn: Bool { user != nil }

    init() {
        apiBase = UserDefaults.standard.string(forKey: "serein.api-base") ?? "https://api.example.invalid"
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

    func signIn(identity: String, password: String) async {
        await authenticate(path: "/api/v1/auth/login", values: [
            "identity": identity.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            "password": password, "device_name": "Serein iOS", "device_id": deviceID
        ])
    }
    func register(username: String, email: String, displayName: String, password: String) async {
        busy = true; errorMessage = nil
        defer { busy = false }
        let cleanEmail = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        do {
            _ = try await request("/api/v1/auth/register", method: "POST", values: [
                "username": username.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                "email": cleanEmail,
                "display_name": displayName.trimmingCharacters(in: .whitespacesAndNewlines),
                "password": password
            ])
            verificationRequired = true; verificationIdentity = cleanEmail; verificationEmail = cleanEmail
            errorMessage = "Check your email for a six-digit verification code."
        } catch { errorMessage = error.localizedDescription }
    }
    func verifyEmail(code: String, email: String) async {
        busy = true; errorMessage = nil
        defer { busy = false }
        do {
            let data = try await request("/api/v1/auth/verify-email", method: "POST", values: ["email": email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), "code": code, "device_name": "Serein iOS", "device_id": deviceID])
            let reply = try JSONDecoder().decode(SereinAuthReply.self, from: data)
            user = reply.account.user; currentDevice = reply.account.device
            defaults.set(reply.account.device.id, forKey: "serein.device-id")
            verificationRequired = false; verificationIdentity = ""; verificationEmail = ""
            await refreshAccountData()
        } catch { errorMessage = error.localizedDescription }
    }
    func resendVerification(identity: String) async {
        busy = true; errorMessage = nil
        defer { busy = false }
        do {
            let data = try await request("/api/v1/auth/resend-verification", method: "POST", values: ["identity": identity.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()])
            let reply = try JSONDecoder().decode(SereinMessageReply.self, from: data)
            errorMessage = reply.message
        } catch { errorMessage = error.localizedDescription }
    }
    private var deviceID: String { defaults.string(forKey: "serein.device-id") ?? UUID().uuidString.lowercased() }

    private func authenticate(path: String, values: [String: Any]) async {
        busy = true; errorMessage = nil
        defer { busy = false }
        do {
            let data = try await request(path, method: "POST", values: values)
            let reply = try JSONDecoder().decode(SereinAuthReply.self, from: data)
            user = reply.account.user; currentDevice = reply.account.device
            defaults.set(reply.account.device.id, forKey: "serein.device-id")
            await refreshAccountData()
        } catch {
            let ns = error as NSError
            if path == "/api/v1/auth/login", ns.code == 403 {
                let identity = (values["identity"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                verificationRequired = true; verificationIdentity = identity
                verificationEmail = identity.contains("@") ? identity : ""
                errorMessage = "Email verification is required. Request a code and enter the account email address."
            } else { errorMessage = error.localizedDescription }
        }
    }
    func restoreSession() async {
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
            fontScale = (prefs["font_scale"] as? String) == "large" ? "large" : "standard"
            reduceMotion = prefs["reduce_motion"] as? Bool ?? false
            notifications = prefs["notifications"] as? Bool ?? false
            presenceVisibility = (prefs["presence_visibility"] as? String) == "nobody" ? "nobody" : "contacts"
            allowContactRequests = prefs["allow_contact_requests"] as? Bool ?? true
            discoverableByEmail = prefs["discoverable_by_email"] as? Bool ?? false
            errorMessage = nil
        } catch { errorMessage = error.localizedDescription }
    }
    func messageHistory(afterCreatedAt: String? = nil, afterID: String? = nil) async throws -> Data {
        var components = URLComponents(); components.path = "/api/v1/messages"
        var items = [URLQueryItem(name: "limit", value: "100")]
        if let afterCreatedAt, let afterID { items.append(URLQueryItem(name: "after_created_at", value: afterCreatedAt)); items.append(URLQueryItem(name: "after_id", value: afterID)) }
        components.queryItems = items
        return try await request(components.string ?? "/api/v1/messages?limit=100")
    }
    func acknowledgeMessage(_ id: String) async throws { _ = try await request("/api/v1/messages/\(id)/ack", method: "POST", values: [:]) }
    func sendEncryptedEnvelope(id: String, to deviceID: String, iv: String, ciphertext: String) async throws {
        _ = try await request("/api/v1/messages", method: "POST", values: ["id": id, "to": deviceID, "iv": iv, "ciphertext": ciphertext])
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
    func savePreferences() async {
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
    func signOut() async {
        do { _ = try await request("/api/v1/auth/logout", method: "POST", values: [:]) }
        catch { errorMessage = error.localizedDescription }
        user = nil; currentDevice = nil; contacts = []; contactRequests = []; blocks = []; devices = []
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
            let detail = (try? JSONDecoder().decode(SereinErrorReply.self, from: data).error) ?? "API request failed (\(http.statusCode))."
            throw NSError(domain: "SereinAPI", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: detail])
        }
        return data
    }
}
