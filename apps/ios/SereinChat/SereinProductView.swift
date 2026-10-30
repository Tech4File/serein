import SwiftUI
import UIKit
import UserNotifications
import UniformTypeIdentifiers
import AVKit
import QuickLook

private struct SereinBackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var bytes: Data
    init(bytes: Data) { self.bytes = bytes }
    init(configuration: ReadConfiguration) throws {
        guard let contents = configuration.file.regularFileContents else { throw SereinBackupStore.BackupError.malformed }
        bytes = contents
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: bytes) }
}

struct SereinProductRootView: View {
    @StateObject private var api = SereinAPI()
    @Environment(\.dynamicTypeSize) private var systemDynamicTypeSize
    @Environment(\.accessibilityReduceMotion) private var systemReduceMotion
    @AppStorage("serein.restore-prompt-done") private var restorePromptDone = false
    @State private var showingRestoreOnboarding = false
    @AppStorage("serein.theme") private var theme = "system"
    @AppStorage("serein.whats-new.version") private var lastWhatsNewVersion = ""
    @State private var showingWhatsNew = false
    @State private var showingError = false
    private var displayedAppVersion: String {
        let version = Bundle.main.infoDictionary?["SereinVersion"] as? String ?? (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown")
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String
        return build.map { "\(version) · build \($0)" } ?? version
    }
    private var effectiveDynamicTypeSize: DynamicTypeSize {
        let minimum: DynamicTypeSize = api.fontScale == "extra_large" ? SereinTokens.fontScaleExtraLargeMinimum : SereinTokens.fontScaleLargeMinimum
        guard api.fontScale != "system" else { return systemDynamicTypeSize }
        return systemDynamicTypeSize < minimum ? minimum : systemDynamicTypeSize
    }
    var body: some View {
        ZStack {
            Group {
                if api.signedIn { SereinProductTabs(api: api) }
                else { SereinNativeAuthView(api: api) }
            }
            if !api.startupReady {
                SereinStartupCurtain().transition(.opacity.combined(with: .move(edge: .top))).zIndex(100)
            }
        }
        .animation(api.reduceMotion || systemReduceMotion ? nil : .easeInOut(duration: 0.55), value: api.startupReady)
        .tint(SereinPalette.green)
        .environment(\.dynamicTypeSize, effectiveDynamicTypeSize)
        .transaction { transaction in
            if api.reduceMotion || systemReduceMotion {
                transaction.animation = nil
                transaction.disablesAnimations = true
            }
        }
        .onChange(of: api.errorMessage) { value in showingError = value != nil }
        .onChange(of: api.theme) { value in theme = value }
        .alert("Serein", isPresented: $showingError) {
            Button("OK", role: .cancel) { api.errorMessage = nil }
        } message: { Text(api.errorMessage ?? "") }
        .onAppear { if api.startupReady { if lastWhatsNewVersion != displayedAppVersion { showingWhatsNew = true } else { scheduleRestorePrompt() } } }
        .onChange(of: api.startupReady) { ready in if ready { if lastWhatsNewVersion != displayedAppVersion { showingWhatsNew = true } else { scheduleRestorePrompt() } } }
        .onChange(of: api.user?.id) { userID in if userID != nil && api.startupReady { scheduleRestorePrompt() } }
        .sheet(isPresented: $showingWhatsNew) { SereinWhatsNewView(version: displayedAppVersion, isFirstInstall: lastWhatsNewVersion.isEmpty) { lastWhatsNewVersion = displayedAppVersion; showingWhatsNew = false; scheduleRestorePrompt() } }
        .sheet(isPresented: $showingRestoreOnboarding) { SereinBackupRestoreOnboarding(api: api) { restorePromptDone = true; showingRestoreOnboarding = false } }
    }
    @MainActor private func scheduleRestorePrompt() {
        guard api.signedIn, !restorePromptDone else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
            if showingWhatsNew { scheduleRestorePrompt(); return }
            if api.signedIn && !restorePromptDone { showingRestoreOnboarding = true }
        }
    }
}

private struct SereinStartupCurtain: View {
    var body: some View {
        GeometryReader { geometry in
            ZStack {
                Color(red: 0.035, green: 0.08, blue: 0.10)
                HStack(spacing: 2) {
                    curtainPanel
                    curtainPanel
                }
                .overlay(alignment: .center) {
                    VStack(spacing: 12) {
                        Image(systemName: "lock.fill").font(.system(size: 28, weight: .medium)).foregroundStyle(.white)
                        Text("SEREIN").font(.system(size: 19, weight: .bold, design: .rounded)).tracking(3).foregroundStyle(.white)
                        ProgressView().tint(.white).padding(.top, 2)
                        Text("Restoring your secure session…").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.white.opacity(0.78))
                    }.padding(22).background(.black.opacity(0.17), in: RoundedRectangle(cornerRadius: 18))
                }
                .frame(width: geometry.size.width, height: geometry.size.height)
            }
            .ignoresSafeArea()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Serein is restoring your secure session")
    }
    private var curtainPanel: some View {
        Rectangle().fill(LinearGradient(colors: [Color(red: 0.34, green: 0.08, blue: 0.13), Color(red: 0.52, green: 0.12, blue: 0.18), Color(red: 0.34, green: 0.08, blue: 0.13)], startPoint: .leading, endPoint: .trailing))
            .overlay(alignment: .leading) { Rectangle().fill(Color.white.opacity(0.035)).frame(width: 2) }
            .overlay(alignment: .trailing) { Rectangle().fill(Color.black.opacity(0.12)).frame(width: 2) }
    }
}

private struct SereinWhatsNewView: View {
    let version: String
    let isFirstInstall: Bool
    let onContinue: () -> Void
    var body: some View {
        NavigationView {
            List {
                Section { Text("Version \(version)").font(.system(size: 13, weight: .semibold, relativeTo: .body)).foregroundStyle(SereinPalette.green) }
                Section("Highlights") {
                    Label("Email verification and stronger account safeguards", systemImage: "checkmark.shield")
                    Label("Contact, privacy, and registered-device settings", systemImage: "person.2")
                    Label("Check or change your self-hosted server connection", systemImage: "network")
                    Label("Native and web chats require explicit per-device fingerprint verification", systemImage: "lock.shield")
                    Label("Notification permissions can be requested in Settings; sound is configurable", systemImage: "bell.badge")
                }
            }.listStyle(.insetGrouped).navigationTitle(isFirstInstall ? "Welcome to Serein" : "What’s New")
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Continue", action: onContinue) } }
        }
        .interactiveDismissDisabled()
    }
}

private struct SereinNativeAuthView: View {
    @ObservedObject var api: SereinAPI
    @State private var registering = false
    @State private var displayName = ""
    @State private var username = ""
    @State private var email = ""
    @State private var password = ""
    @State private var passwordVisible = false
    @State private var otpDigits = Array(repeating: "", count: 6)
    @State private var verifyingOtp = false
    @State private var resendSeconds = 0
    @State private var showConnectionSettings = false
    @FocusState private var focusedOtp: Int?
    var body: some View {
        ZStack {
            LinearGradient(colors: [Color(uiColor: .systemBackground), SereinPalette.paleMint.opacity(0.45)], startPoint: .topLeading, endPoint: .bottomTrailing).ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack { SereinAvatar(name: "Serein", size: 42); VStack(alignment: .leading) { Text("Serein").font(.system(size: 20, weight: .bold, design: .rounded, relativeTo: .body)); Text("SEREIN ACCOUNT").font(.system(size: 10, weight: .bold, relativeTo: .body)).tracking(1.1).foregroundStyle(.secondary) }; Spacer(); Button { showConnectionSettings = true } label: { Label("Connection", systemImage: "network").font(.system(size: 10, weight: .semibold, relativeTo: .body)) } }
                    VStack(alignment: .leading, spacing: 7) { SereinSectionLabel(title: api.verificationRequired ? (api.verificationPurpose == "login" ? "TWO-STEP SIGN-IN" : "EMAIL VERIFICATION") : "ACCOUNT"); Text(api.verificationRequired ? (api.verificationPurpose == "login" ? "Finish signing in" : "Verify your email") : (registering ? "Create your account" : "Welcome back")).font(.system(size: 29, weight: .bold, design: .rounded, relativeTo: .body)); Text(api.verificationRequired ? (api.verificationPurpose == "login" ? "Enter the emailed code; your password is also required." : "Enter the six-digit code sent to your inbox.") : "Connect to your Serein API over HTTPS.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary) }
                    SereinCard {
                        VStack(spacing: 13) {
                            if let status = api.statusMessage, !status.isEmpty { Text(status).font(.system(size: 10, relativeTo: .body)).foregroundStyle(SereinPalette.green).frame(maxWidth: .infinity, alignment: .leading) }
                            if api.verificationRequired {
                                VStack(spacing: 15) {
                                    Text("A code was sent to \(api.verificationEmail)").font(.system(size: 11, weight: .medium, relativeTo: .body)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).lineLimit(2)
                                    HStack(spacing: 8) {
                                        ForEach(0..<6, id: \.self) { index in
                                            TextField("", text: Binding(get: { otpDigits[index] }, set: { setOtpDigit(index, value: $0) }))
                                                .keyboardType(.numberPad).textContentType(index == 0 ? .oneTimeCode : nil).textInputAutocapitalization(.never)
                                                .font(.system(size: 20, weight: .semibold, design: .monospaced, relativeTo: .body)).multilineTextAlignment(.center)
                                                .focused($focusedOtp, equals: index).frame(maxWidth: .infinity).frame(height: 43)
                                                .overlay(alignment: .bottom) { Rectangle().fill(focusedOtp == index ? SereinPalette.green : Color.secondary.opacity(0.35)).frame(height: 2) }
                                                .accessibilityLabel("Code digit \(index + 1)")
                                        }
                                    }
                                    Button { verifyOtp() } label: {
                                        HStack { Spacer(); if verifyingOtp || api.busy { ProgressView().tint(.white) }; Text(verifyingOtp || api.busy ? "Verifying…" : (otpDigits.joined().count == 6 ? (api.verificationPurpose == "login" ? "Finish sign-in" : "Verify email") : "Enter the six-digit code")); Spacer(); if !(verifyingOtp || api.busy) { Image(systemName: "arrow.right") } }
                                    }.buttonStyle(SereinPrimaryButtonStyle()).disabled(api.busy || verifyingOtp || api.verificationEmail.isEmpty || otpDigits.joined().count != 6)
                                    HStack {
                                        Button(resendButtonTitle) { Task { if let seconds = await api.resendVerification(identity: api.verificationEmail) { startResendCooldown(seconds) } } }.disabled(api.busy || verifyingOtp || resendSeconds > 0 || api.verificationEmail.isEmpty)
                                        Spacer()
                                        Button("← Back to sign in") { api.cancelVerification(); registering = false; resendSeconds = 0; otpDigits = Array(repeating: "", count: 6) }.font(.system(size: 11, weight: .medium, relativeTo: .body))
                                    }.font(.system(size: 11, relativeTo: .body))
                                }.onAppear { focusedOtp = 0 }
                            } else {
                                Button { showConnectionSettings = true } label: { HStack { Image(systemName: "network"); VStack(alignment: .leading) { Text("Server connection").font(.system(size: 11, weight: .semibold, relativeTo: .body)); Text(api.connectionStatus).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Spacer(); Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold, relativeTo: .body)) }.foregroundStyle(SereinPalette.green).padding(12).frame(maxWidth: .infinity, alignment: .leading).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11)) }
                                HStack(spacing: 6) { modeButton("Sign in", active: !registering) { withAnimation(.easeInOut(duration: 0.2)) { registering = false } }; modeButton("Create account", active: registering) { withAnimation(.easeInOut(duration: 0.2)) { registering = true } } }
                                if registering {
                                    input("Display name", text: $displayName, icon: "person")
                                    input("Username", text: $username, icon: "at")
                                    input("Email", text: $email, icon: "envelope")
                                } else { input("Username or email", text: $username, icon: "person") }
                                HStack { Image(systemName: "lock").foregroundStyle(.secondary); Group { if passwordVisible { TextField("Password", text: $password) } else { SecureField("Password", text: $password) } }.textInputAutocapitalization(.never).autocorrectionDisabled(); Button { passwordVisible.toggle() } label: { Image(systemName: passwordVisible ? "eye.slash" : "eye") }.accessibilityLabel(passwordVisible ? "Hide password" : "Show password") }.padding(12).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
                                if registering {
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text("Password requirements").font(.system(size: 10, weight: .semibold, relativeTo: .body)).foregroundStyle(.secondary)
                                        requirement("At least 8 characters", met: password.unicodeScalars.count >= 8)
                                        requirement("At least one uppercase letter (A–Z)", met: passwordHasUppercase)
                                        requirement("At least one lowercase letter (a–z)", met: passwordHasLowercase)
                                        requirement("At least one number (0–9)", met: passwordHasNumber)
                                        requirement("No more than 1024 UTF-8 bytes", met: password.utf8.count <= 1024)
                                    }.padding(11).frame(maxWidth: .infinity, alignment: .leading).background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10)).transition(.opacity.combined(with: .move(edge: .top)))
                                    Text("New accounts must verify their email before signing in. A code is sent by the server after registration.").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                                }
                                Button { Task { if registering { await api.register(username: username, email: email, displayName: displayName, password: password) } else { await api.signIn(identity: username, password: password) } } } label: {
                                    HStack { Spacer(); Text(api.busy ? "Connecting…" : (registering ? "Create account" : "Sign in")); Spacer(); Image(systemName: "arrow.right") }
                                }.buttonStyle(SereinPrimaryButtonStyle()).disabled(api.busy || (registering && !validRegistrationPassword) || username.isEmpty).animation(.easeInOut(duration: 0.2), value: registering)
                            }
                        }
                    }
                    if !api.verificationRequired { Text("After sign-in, open a contact to set up encrypted native messaging. Verify every current device fingerprint before sending.").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }
                }.padding(22).frame(maxWidth: 540).frame(maxWidth: .infinity)
            }
        }.sheet(isPresented: $showConnectionSettings) { SereinConnectionSettings(api: api) }
    }
    private func input(_ title: String, text: Binding<String>, icon: String) -> some View {
        HStack { Image(systemName: icon).foregroundStyle(.secondary); TextField(title, text: text).textInputAutocapitalization(.never).autocorrectionDisabled() }.padding(12).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
    }
    private var passwordHasUppercase: Bool { password.unicodeScalars.contains { $0.value >= 65 && $0.value <= 90 } }
    private var passwordHasLowercase: Bool { password.unicodeScalars.contains { $0.value >= 97 && $0.value <= 122 } }
    private var passwordHasNumber: Bool { password.unicodeScalars.contains { $0.value >= 48 && $0.value <= 57 } }
    private var validRegistrationPassword: Bool { password.unicodeScalars.count >= 8 && passwordHasUppercase && passwordHasLowercase && passwordHasNumber && password.utf8.count <= 1024 }
    private var resendButtonTitle: String { resendSeconds > 0 ? String(format: "Resend in %02d:%02d", resendSeconds / 60, resendSeconds % 60) : "Resend code" }
    private func startResendCooldown(_ seconds: Int) {
        resendSeconds = max(1, min(seconds, 3600))
        Task { @MainActor in
            while resendSeconds > 0 {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                if Task.isCancelled { return }
                resendSeconds = max(0, resendSeconds - 1)
            }
        }
    }
    private func setOtpDigit(_ index: Int, value: String) {
        let digits = value.filter { $0.isASCII && $0.isNumber }
        if digits.count > 1 {
            let code = Array(digits.prefix(6)).map { String($0) }
            otpDigits = code + Array(repeating: "", count: max(0, 6 - code.count))
            focusedOtp = code.count < 6 ? code.count : nil
        } else {
            otpDigits[index] = digits.isEmpty ? "" : String(digits.prefix(1))
            if !otpDigits[index].isEmpty { focusedOtp = index < 5 ? index + 1 : nil }
        }
        if otpDigits.joined().count == 6 && !api.busy && !verifyingOtp { verifyOtp() }
    }
    private func verifyOtp() {
        guard otpDigits.joined().count == 6, !api.verificationEmail.isEmpty, !api.busy, !verifyingOtp else { return }
        verifyingOtp = true
        Task { await api.verifyEmail(code: otpDigits.joined(), email: api.verificationEmail); verifyingOtp = false }
    }
    private func requirement(_ title: String, met: Bool) -> some View {
        Label(title, systemImage: met ? "checkmark.circle.fill" : "circle").font(.system(size: 10, relativeTo: .body)).foregroundStyle(met ? SereinPalette.green : Color.secondary)
    }
    private func modeButton(_ title: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) { Text(title).font(.system(size: 11, weight: .semibold, relativeTo: .body)).frame(maxWidth: .infinity).padding(10).background(active ? SereinPalette.paleMint : Color.clear, in: RoundedRectangle(cornerRadius: 9)) }
    }
}

private struct SereinProductTabs: View {
    @ObservedObject var api: SereinAPI
    var body: some View {
        TabView {
            SereinNativeChats(api: api).tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right") }
            SereinNativeContacts(api: api).tabItem { Label("Contacts", systemImage: "person.2") }
            SereinNativeSettings(api: api).tabItem { Label("Settings", systemImage: "slider.horizontal.3") }
        }
    }
}

private struct SereinNativeChats: View {
    @ObservedObject var api: SereinAPI
    var body: some View {
        NavigationView {
            Group {
                if api.contacts.isEmpty {
                    VStack(spacing: 12) { Image(systemName: "bubble.left.and.bubble.right").font(.system(size: 36, relativeTo: .body)).foregroundStyle(SereinPalette.green); Text("No contacts yet").font(.system(size: 20, weight: .bold, relativeTo: .body)); Text("Add a username from Contacts, verify the device fingerprints, and start an encrypted conversation.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary).multilineTextAlignment(.center).padding(.horizontal, 28); Button("Refresh") { Task { await api.refreshAccountData() } } }
                } else {
                    List(api.contacts) { contact in
                        NavigationLink(destination: SereinNativeConversation(api: api, contact: contact)) {
                            HStack(spacing: 11) {
                                SereinAvatar(name: contact.display_name, size: 42)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(contact.display_name).font(.system(size: 13, weight: .semibold, relativeTo: .body))
                                    Text(contact.isDeleted ? "Deleted account · archived read-only chat" : "@\(contact.username) · \(contact.online ? "Online" : "Offline")").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if !contact.isDeleted { Text("\(contact.devices.count) devices").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.tertiary) }
                            }
                        }
                    }.listStyle(.insetGrouped)
                }
            }.navigationTitle("Chats").toolbar { ToolbarItem(placement: .navigationBarTrailing) { Button { Task { await api.refreshAccountData() } } label: { Image(systemName: "arrow.clockwise") } } }
        }
    }
}

private struct SereinConversationSystemEvent: View {
    let text: String
    let timestamp: String
    private var formattedTimestamp: String {
        let parser = ISO8601DateFormatter()
        guard let date = parser.date(from: timestamp) else { return timestamp }
        let formatter = DateFormatter(); formatter.dateStyle = .medium; formatter.timeStyle = .short
        return formatter.string(from: date)
    }
    var body: some View {
        VStack(spacing: 4) { Text(text); Text(formattedTimestamp).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.tertiary) }
            .font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary).multilineTextAlignment(.center)
            .padding(.horizontal, 14).padding(.vertical, 9).frame(maxWidth: .infinity)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }
}

private final class SereinGIFNoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}

private struct SereinNativeGIFResult: Identifiable, Hashable {
    let url: URL
    let title: String
    var id: String { url.absoluteString }
}

private struct SereinNativeGIFPicker: View {
    let onSelect: (URL) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var categories: [String] = []
    @State private var category = "hug"
    @State private var query = ""
    @State private var results: [SereinNativeGIFResult] = []
    @State private var seen = Set<String>()
    @State private var loading = false
    @State private var exhausted = false
    @State private var repeatedBatches = 0
    @State private var generation = 0
    @State private var status = "Loading GIF categories…"
    @State private var errorMessage: String?
    private let preferred = ["hug", "pat", "wave", "laugh", "dance", "smile"]
    private static let session = URLSession(configuration: .ephemeral, delegate: SereinGIFNoRedirectDelegate(), delegateQueue: nil)
    private let columns = [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)]

    var body: some View {
        NavigationView {
            VStack(spacing: 8) {
                HStack(spacing: 8) {
                    TextField("Search GIFs", text: $query).textFieldStyle(.roundedBorder).submitLabel(.search).onSubmit { Task { await search() } }
                    Button("Search") { Task { await search() } }.disabled(query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 7) {
                        ForEach(categories, id: \.self) { item in
                            Button(item.capitalized) { query="";category=item;resetAndLoad() }
                                .font(.system(size: 11, weight: .semibold, relativeTo: .body))
                                .padding(.horizontal, 12).padding(.vertical, 7)
                                .background(query.isEmpty && category == item ? SereinPalette.paleMint : Color.secondary.opacity(0.1), in: Capsule())
                        }
                    }
                }.frame(height: 36)
                ScrollView {
                    LazyVGrid(columns: columns, spacing: 9) {
                        ForEach(results) { result in
                            Button { Task { await download(result) } } label: {
                                VStack(spacing: 4) {
                                    AsyncImage(url: result.url) { phase in
                                        if let image=phase.image { image.resizable().scaledToFill() }
                                        else { ZStack { Color.secondary.opacity(0.12); if phase.error == nil { ProgressView() } else { Image(systemName: "photo") } } }
                                    }.frame(height: 116).frame(maxWidth: .infinity).clipped().clipShape(RoundedRectangle(cornerRadius: 10))
                                    Text(result.title.isEmpty ? "GIF" : result.title).font(.system(size: 10, relativeTo: .body)).lineLimit(1).foregroundStyle(.primary)
                                }
                            }.buttonStyle(.plain).onAppear { if result.id == results.last?.id { Task { await loadBatch() } } }
                        }
                    }
                    if loading { ProgressView().padding(12) }
                    if let errorMessage { Text(errorMessage).font(.system(size: 11, relativeTo: .body)).foregroundStyle(.red).padding(10) }
                    Text(status+" Search terms and request metadata are sent to nekos.best.").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary).multilineTextAlignment(.center).padding(10)
                    if !exhausted && !results.isEmpty { Button("Load more") { Task { await loadBatch() } }.font(.system(size: 12, weight: .semibold, relativeTo: .body)).padding(.bottom, 12) }
                }
            }.padding(12).navigationTitle("GIFs").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
                .task { await loadCategories() }
        }
    }

    private func loadCategories() async {
        guard categories.isEmpty else { await loadBatch(); return }
        do {
            let (data,response)=try await Self.session.data(from:URL(string:"https://nekos.best/api/v2/endpoints")!)
            guard (response as? HTTPURLResponse)?.statusCode == 200, let payload=try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw URLError(.badServerResponse) }
            let available=Set(payload.compactMap { pair -> String? in ((pair.value as? [String:Any])?["format"] as? String)=="gif" ? pair.key : nil })
            categories=preferred.filter { available.contains($0) }
            if categories.isEmpty { categories=Array(available.sorted().prefix(6)) }
            guard !categories.isEmpty else { throw URLError(.cannotParseResponse) }
            if !categories.contains(category) { category=categories[0] }
            await loadBatch()
        } catch { errorMessage="GIF categories could not load. Try again or attach a local file.";status="GIF service unavailable." }
    }
    private func resetAndLoad() { generation += 1;loading=false;results=[];seen=[];exhausted=false;repeatedBatches=0;errorMessage=nil;Task { await loadBatch() } }
    private func search() async {
        let value=query.trimmingCharacters(in:.whitespacesAndNewlines).split(whereSeparator: \.isWhitespace).joined(separator:" ")
        guard !value.isEmpty else { return }
        generation += 1;loading=false;query=String(value.prefix(80));results=[];seen=[];exhausted=false;repeatedBatches=0;errorMessage=nil;await loadBatch()
    }
    private func loadBatch() async {
        guard !loading && !exhausted else { return };loading=true;let requestGeneration=generation;errorMessage=nil
        var parts=URLComponents(string:"https://nekos.best/api/v2/"+(query.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty ? category : "search"))!
        var items=[URLQueryItem(name:"type",value:"2"),URLQueryItem(name:"amount",value:"15")]
        if !query.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty { items.append(URLQueryItem(name:"query",value:query)) }
        parts.queryItems=items
        do {
            let (data,response)=try await Self.session.data(from:parts.url!)
            guard (response as? HTTPURLResponse)?.statusCode == 200,let payload=try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw URLError(.badServerResponse) }
            guard requestGeneration == generation else { return }
            let raw=payload["results"] as? [[String:Any]] ?? []
            var added=0
            for row in raw {
                guard let string=row["url"] as? String,let url=URL(string:string),url.scheme=="https",url.host=="nekos.best",url.path.hasPrefix("/api/v2/") else { continue }
                if seen.insert(url.absoluteString).inserted { results.append(SereinNativeGIFResult(url:url,title:String((row["anime_name"] as? String ?? "GIF").prefix(80))));added += 1 }
            }
            repeatedBatches=added==0 ? repeatedBatches+1 : 0
            if raw.count<15 || repeatedBatches>=3 || results.count>=120 { exhausted=true }
            loading=false
            status=query.isEmpty ? "\(results.count) GIFs loaded." : "\(results.count) GIFs for ‘\(query)’ ."
        } catch { guard requestGeneration == generation else { return };loading=false;errorMessage="Could not load GIFs: \(error.localizedDescription)" }
    }
    private func download(_ item: SereinNativeGIFResult) async {
        loading=true;defer { loading=false }
        do {
            let (temporary,response)=try await Self.session.download(from:item.url)
            guard (response as? HTTPURLResponse)?.statusCode == 200,(response as? HTTPURLResponse)?.mimeType?.lowercased().hasPrefix("image/")==true else { throw URLError(.cannotDecodeContentData) }
            let values=try temporary.resourceValues(forKeys:[.fileSizeKey]);guard let size=values.fileSize,size>0,size<=64*1024*1024 else { throw URLError(.dataLengthExceedsMaximum) }
            let destination=FileManager.default.temporaryDirectory.appendingPathComponent("serein-nekos-\(UUID().uuidString).gif")
            try FileManager.default.moveItem(at:temporary,to:destination);onSelect(destination);dismiss()
        } catch { errorMessage="GIF download failed: \(error.localizedDescription)" }
    }
}

private struct SereinMediaViewerItem: Identifiable {
    let attachment: SereinEncryptedAttachment
    let url: URL
    var id: String { attachment.transferID }
}

private struct SereinContactProfile: View {
    @ObservedObject var api: SereinAPI
    @ObservedObject var engine: SereinChatEngine
    let contact: SereinContact
    let messages: [SereinChatMessage]
    @Environment(\.dismiss) private var dismiss
    @State private var favorite = false
    @State private var showMediaLibrary = false
    @State private var selectedMedia: SereinMediaViewerItem?
    @State private var openingTransferID: String?
    private var allAttachments: [SereinChatMessage] { messages.filter { $0.attachment != nil }.sorted { $0.createdAt > $1.createdAt } }
    private var latestFour: [SereinChatMessage] { Array(allAttachments.prefix(4)) }
    private var favoriteKey: String { "serein.favorite.\(api.user?.id ?? "local").\(contact.user_id)" }
    var body: some View {
        NavigationView {
            List {
                Section {
                    VStack(spacing: 8) {
                        SereinAvatar(name: contact.display_name, size: 82)
                        Text(contact.display_name).font(.system(size: 22, weight: .bold, relativeTo: .body))
                        Text("@\(contact.username)").font(.system(size: 13, relativeTo: .body)).foregroundStyle(.secondary)
                        Label(contact.email_verified ? "Email verified" : "Email not verified", systemImage: contact.email_verified ? "checkmark.seal.fill" : "exclamationmark.circle")
                            .font(.system(size: 11, relativeTo: .body)).foregroundStyle(contact.email_verified ? SereinPalette.green : .secondary)
                        Text("Private account email is not shared.").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.tertiary)
                    }.frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                Section("About") {
                    profileLine("Username", "@\(contact.username)")
                    profileLine("Active devices", "\(contact.devices.count)")
                    if let connected=contact.connected_at { profileLine("Friends since", profileDate(connected)) }
                }
                Section {
                    HStack { Text("Shared media").font(.system(size: 14, weight: .semibold, relativeTo: .body)); Spacer(); Button("View all") { showMediaLibrary=true }.font(.system(size: 11, weight: .semibold, relativeTo: .body)) }
                    Text("\(allAttachments.count) file\(allAttachments.count == 1 ? "" : "s") · latest four").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                    if latestFour.isEmpty { Text("Shared photos, GIFs, videos, audio and documents will appear here.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary).padding(.vertical, 8) }
                    else {
                        LazyVGrid(columns: [GridItem(.flexible(), spacing: 7), GridItem(.flexible(), spacing: 7)], spacing: 7) {
                            ForEach(latestFour) { message in
                                if let attachment=message.attachment {
                                    SereinCompactMediaTile(attachment: attachment, localURL: engine.localFile(for: attachment), isLoading: openingTransferID == attachment.transferID) {
                                        openMedia(attachment)
                                    }
                                }
                            }
                        }.padding(.vertical, 3)
                    }
                }
                Section {
                    Toggle(isOn: $favorite) { Label("Favorite", systemImage: favorite ? "star.fill" : "star") }
                        .onChange(of: favorite) { value in UserDefaults.standard.set(value, forKey: favoriteKey) }
                    Button(role: .destructive) { Task { await api.block(contact); dismiss() } } label: { Label("Block contact", systemImage: "hand.raised.fill") }
                        .disabled(contact.isDeleted)
                }
            }.listStyle(.insetGrouped).navigationTitle("Contact profile").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
                .onAppear { favorite=UserDefaults.standard.bool(forKey:favoriteKey) }
        }
        .fullScreenCover(isPresented: $showMediaLibrary) {
            SereinMediaLibrary(engine: engine, messages: allAttachments, onClose: { showMediaLibrary=false })
        }
        .fullScreenCover(item: $selectedMedia) { item in SereinDirectMediaViewer(item: item) }
    }
    private func openMedia(_ attachment: SereinEncryptedAttachment) {
        guard openingTransferID == nil else { return }
        openingTransferID=attachment.transferID
        Task {
            var url=engine.localFile(for:attachment)
            if url == nil { url=await engine.download(attachment) }
            openingTransferID=nil
            if let url { selectedMedia=SereinMediaViewerItem(attachment:attachment,url:url) }
        }
    }
    @ViewBuilder private func profileLine(_ title: String, _ value: String) -> some View { HStack { Text(title).foregroundStyle(.secondary); Spacer(); Text(value).multilineTextAlignment(.trailing) }.font(.system(size: 12, relativeTo: .body)) }
    private func profileDate(_ value: String) -> String { guard let date=ISO8601DateFormatter().date(from:value) else { return value };let f=DateFormatter();f.dateStyle = .medium;return f.string(from:date) }
}

private struct SereinCompactMediaTile: View {
    let attachment: SereinEncryptedAttachment
    let localURL: URL?
    let isLoading: Bool
    let action: () -> Void
    private var kind: String { SereinMediaLibrary.kind(for: attachment) }
    var body: some View {
        Button(action:action) {
            VStack(alignment:.leading,spacing:5) {
                ZStack {
                    RoundedRectangle(cornerRadius:9).fill(Color.secondary.opacity(0.10))
                    if (kind == "photo" || kind == "gif"),let localURL,let image=UIImage(contentsOfFile:localURL.path) { Image(uiImage:image).resizable().scaledToFill().frame(maxWidth:.infinity).frame(height:78).clipped().clipShape(RoundedRectangle(cornerRadius:9)) }
                    else { Image(systemName:kind == "video" ? "play.rectangle.fill" : kind == "audio" ? "waveform" : kind == "gif" ? "sparkles" : kind == "photo" ? "photo" : "doc.fill").font(.system(size:22,weight:.medium)).foregroundStyle(SereinPalette.green) }
                    if isLoading { ProgressView().padding(5).background(.thinMaterial,in:Circle()) }
                }.frame(height:78).frame(maxWidth:.infinity).clipped()
                Text(attachment.filename).font(.system(size:10,weight:.medium,relativeTo:.body)).lineLimit(1).frame(maxWidth:.infinity,alignment:.leading)
                Text("\(kind.capitalized) · \(SereinMediaLibrary.bytes(attachment.size))").font(.system(size:9,relativeTo:.body)).foregroundStyle(.secondary).lineLimit(1)
            }.padding(6).background(Color.secondary.opacity(0.07),in:RoundedRectangle(cornerRadius:11))
        }.buttonStyle(.plain).disabled(isLoading)
    }
}

private struct SereinMediaLibrary: View {
    @ObservedObject var engine:SereinChatEngine
    let messages: [SereinChatMessage]
    let onClose: () -> Void
    @State private var selectedTab="media"
    @State private var mediaFilter="all"
    @State private var selectedMedia:SereinMediaViewerItem?
    @State private var openingTransferID:String?
    private let columns=[GridItem(.flexible(),spacing:9),GridItem(.flexible(),spacing:9)]
    private var attachments:[SereinEncryptedAttachment]{messages.filter{$0.attachment != nil}.sorted{$0.createdAt>$1.createdAt}.compactMap(\.attachment)}
    private var displayed:[SereinEncryptedAttachment]{attachments.filter{attachment in let kind=Self.kind(for:attachment);if selectedTab=="documents"{return kind=="document"};return kind != "document" && (mediaFilter=="all" || kind==mediaFilter)}}
    var body: some View {
        NavigationView {
            VStack(spacing:8) {
                HStack(spacing:5) {
                    tabButton("Media",value:"media");tabButton("Documents",value:"documents")
                }.padding(4).background(Color.secondary.opacity(0.10),in:RoundedRectangle(cornerRadius:12))
                if selectedTab=="media" { ScrollView(.horizontal,showsIndicators:false) { HStack(spacing:7) { for (label,value) in [("All","all"),("Photos","photo"),("GIFs","gif"),("Videos","video"),("Audio","audio")] { Button(label){mediaFilter=value}.font(.system(size:11,weight:.semibold,relativeTo:.body)).padding(.horizontal,12).padding(.vertical,7).background(mediaFilter==value ? SereinPalette.paleMint : Color.secondary.opacity(0.09),in:Capsule()) } } }.frame(height:34) }
                Text("\(displayed.count) \(selectedTab == "documents" ? "documents" : "media files") · newest first").font(.system(size:10,relativeTo:.body)).foregroundStyle(.secondary).frame(maxWidth:.infinity,alignment:.leading)
                if displayed.isEmpty { Spacer();VStack(spacing:10){Image(systemName:selectedTab=="documents" ? "doc" : "photo.on.rectangle.angled").font(.system(size:32)).foregroundStyle(.secondary);Text(selectedTab=="documents" ? "No documents yet" : "No media yet").font(.system(size:16,weight:.semibold));Text("Files shared in this conversation will appear here.").font(.system(size:11)).foregroundStyle(.secondary).multilineTextAlignment(.center)}.padding(24);Spacer() }
                else { ScrollView { LazyVGrid(columns:columns,spacing:9) { ForEach(displayed,id:\.transferID) { attachment in SereinCompactMediaTile(attachment:attachment,localURL:engine.localFile(for:attachment),isLoading:openingTransferID==attachment.transferID){openMedia(attachment)} } }.padding(.vertical,7) } }
            }.padding(12).navigationTitle("Shared files").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement:.cancellationAction) { Button("Close",action:onClose) } }
        }
        .fullScreenCover(item:$selectedMedia){item in SereinDirectMediaViewer(item:item)}
    }
    private func openMedia(_ attachment:SereinEncryptedAttachment){guard openingTransferID==nil else{return};openingTransferID=attachment.transferID;Task{var url=engine.localFile(for:attachment);if url==nil{url=await engine.download(attachment)};openingTransferID=nil;if let url{selectedMedia=SereinMediaViewerItem(attachment:attachment,url:url)}}}
    private func tabButton(_ title:String,value:String)->some View { Button { selectedTab=value } label:{ Text(title).font(.system(size:13,weight:.semibold,relativeTo:.body)).frame(maxWidth:.infinity).padding(.vertical,9).background(selectedTab==value ? Color(uiColor:.systemBackground) : .clear,in:RoundedRectangle(cornerRadius:9)) }.buttonStyle(.plain) }
    static func kind(for attachment:SereinEncryptedAttachment)->String { let type=attachment.contentType.lowercased(),name=attachment.filename.lowercased();if type=="image/gif" || name.hasSuffix(".gif"){return "gif"};if type.hasPrefix("image/"){return "photo"};if type.hasPrefix("video/"){return "video"};if type.hasPrefix("audio/"){return "audio"};return "document" }
    static func bytes(_ size:Int64)->String { if size<1024{return "\(size) B"};if size<1_048_576{return String(format:"%.1f KB",Double(size)/1024)};return String(format:"%.1f MB",Double(size)/1_048_576) }
}

private struct SereinDirectMediaViewer: View {
    let item:SereinMediaViewerItem
    @Environment(\.dismiss) private var dismiss
    @State private var player:AVPlayer?
    private var kind:String { SereinMediaLibrary.kind(for:item.attachment) }
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing:12) {
                HStack { VStack(alignment:.leading,spacing:2){Text(item.attachment.filename).font(.system(size:14,weight:.semibold)).lineLimit(1);Text("\(item.attachment.contentType) · \(SereinMediaLibrary.bytes(item.attachment.size))").font(.system(size:10)).foregroundStyle(.white.opacity(0.7))};Spacer();Button("Done"){player?.pause();dismiss()}.font(.system(size:12,weight:.semibold)).padding(.horizontal,12).padding(.vertical,8).background(.white.opacity(0.13),in:Capsule()) }.foregroundStyle(.white).padding(.horizontal,14).padding(.top,8)
                Spacer(minLength:8)
                if kind=="photo" || kind=="gif" {
                    if let image=UIImage(contentsOfFile:item.url.path){Image(uiImage:image).resizable().scaledToFit().frame(maxWidth:.infinity,maxHeight:.infinity)}else{VStack(spacing:8){Image(systemName:"photo").font(.system(size:38));Text("Preview unavailable").font(.system(size:13))}.foregroundStyle(.white.opacity(0.8))}
                } else if kind=="video" { if let player { VideoPlayer(player:player).frame(maxWidth:.infinity,maxHeight:.infinity).onAppear{player.play()} } else { ProgressView().tint(.white) } }
                else if kind=="audio" { VStack(spacing:12){Image(systemName:"waveform").font(.system(size:64)).foregroundStyle(.white);if let player { VideoPlayer(player:player).frame(height:90) } else { ProgressView().tint(.white) }} }
                else { SereinQuickLookDocument(url:item.url).frame(maxWidth:.infinity,maxHeight:.infinity) }
                Spacer(minLength:8)
                HStack { Text("Saved in Serein’s on-device Downloads folder.").font(.system(size:10)).foregroundStyle(.white.opacity(0.68));Spacer();Button("Open in…"){if let view=UIApplication.shared.connectedScenes.compactMap({$0 as? UIWindowScene}).flatMap(\.windows).first(where:{$0.isKeyWindow})?.rootViewController{try? SereinAttachmentStore.shared.open(item.url,from:view)}}.font(.system(size:11,weight:.semibold)) }.foregroundStyle(.white).padding(.horizontal,14).padding(.bottom,12)
            }
        }.onAppear{if kind=="video" || kind=="audio"{player=AVPlayer(url:item.url)}}.onDisappear{player?.pause()}
    }
}

private struct SereinQuickLookDocument: UIViewControllerRepresentable {
    let url:URL
    func makeCoordinator()->Coordinator{Coordinator(url:url)}
    func makeUIViewController(context:Context)->QLPreviewController{let controller=QLPreviewController();controller.dataSource=context.coordinator;return controller}
    func updateUIViewController(_ controller:QLPreviewController,context:Context){}
    final class Coordinator:NSObject,QLPreviewControllerDataSource {
        let url:URL
        init(url:URL){self.url=url}
        func numberOfPreviewItems(in controller:QLPreviewController)->Int{1}
        func previewController(_ controller:QLPreviewController,previewItemAt index:Int)->QLPreviewItem{url as NSURL}
    }
}

private struct SereinConversationTimelineItem: Identifiable {
    let id: String
    let createdAt: String
    let message: SereinChatMessage?
    let eventText: String?
    var startsNewDay = false
}

private struct SereinConversationDaySeparator: View {
    let timestamp: String
    private var title: String {
        guard let date=ISO8601DateFormatter().date(from:timestamp) else { return timestamp }
        if Calendar.current.isDateInToday(date) { return "Today" }
        if Calendar.current.isDateInYesterday(date) { return "Yesterday" }
        let formatter=DateFormatter();formatter.dateFormat=Calendar.current.component(.year, from: date)==Calendar.current.component(.year, from: Date()) ? "EEEE, MMM d" : "EEEE, MMM d, yyyy";return formatter.string(from:date)
    }
    var body: some View { Text(title.uppercased()).font(.system(size: 10, weight: .semibold, relativeTo: .body)).tracking(0.5).foregroundStyle(.secondary).padding(.horizontal,12).padding(.vertical,6).background(Color.secondary.opacity(0.09),in:Capsule()).frame(maxWidth:.infinity).padding(.vertical,4) }
}

private struct SereinConversationWallpaper: View {
    @Environment(\.colorScheme) private var colorScheme
    var body: some View {
        Canvas { context, size in
            let dark = colorScheme == .dark
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(dark ? Color(red: 0.043, green: 0.078, blue: 0.102) : Color(red: 0.925, green: 0.918, blue: 0.886)))
            let ink = dark ? Color(red: 0.12, green: 0.19, blue: 0.22).opacity(0.75) : Color(red: 0.69, green: 0.70, blue: 0.66).opacity(0.42)
            var y: CGFloat = 24
            var row = 0
            while y < size.height + 70 {
                var x: CGFloat = row.isMultiple(of: 2) ? 22 : 58
                while x < size.width + 60 {
                    let rect = CGRect(x: x, y: y, width: 30, height: 20)
                    var bubble = Path(roundedRect: rect, cornerSize: CGSize(width: 6, height: 6))
                    bubble.move(to: CGPoint(x: x + 8, y: y + 20)); bubble.addLine(to: CGPoint(x: x + 4, y: y + 25)); bubble.addLine(to: CGPoint(x: x + 14, y: y + 20))
                    context.stroke(bubble, with: .color(ink), lineWidth: 1.2)
                    let dotY = y + 10
                    for offset in [CGFloat(10), CGFloat(15), CGFloat(20)] {
                        var dot = Path(); dot.addEllipse(in: CGRect(x: x + offset - 1, y: dotY - 1, width: 2, height: 2))
                        context.fill(dot, with: .color(ink))
                    }
                    var circle = Path(); circle.addEllipse(in: CGRect(x: x + 42, y: y + 2, width: 18, height: 18))
                    context.stroke(circle, with: .color(ink), lineWidth: 1.1)
                    x += 104
                }
                y += 78; row += 1
            }
        }
        .accessibilityHidden(true)
    }
}

private struct SereinNativeConversation: View {
    let contact: SereinContact
    @ObservedObject private var api: SereinAPI
    @StateObject private var engine: SereinChatEngine
    @State private var showProfile = false
    @State private var showGIFPicker = false
    @State private var draft = ""
    @State private var showKeys = false
    @State private var showFilePicker = false
    @State private var showEmojiPicker = false
    @State private var pendingTrust: SereinPeerKey?
    @State private var fileToOpen: OpenAttachment?
    @Environment(\.colorScheme) private var colorScheme

    private var outgoingBubble: Color { colorScheme == .dark ? Color(red: 0.02, green: 0.36, blue: 0.32) : Color(red: 0.84, green: 0.96, blue: 0.87) }
    private var incomingBubble: Color { colorScheme == .dark ? Color(uiColor: .secondarySystemBackground) : Color.white }
    private var securitySummary: String {
        if contact.isDeleted || engine.archived { return "Archived · read only" }
        guard engine.ready else { return "Preparing secure messaging…" }
        let detail = engine.status
        if detail.hasPrefix("All ") && detail.localizedCaseInsensitiveContains("verified") { return "Encryption ready · verified devices" }
        if detail.hasPrefix("Verify ") { return "Security setup required" }
        if detail.localizedCaseInsensitiveContains("not published") { return "Recipient keys unavailable" }
        if detail.hasPrefix("No active") { return "No active recipient devices" }
        return "Review security details"
    }

    init(api: SereinAPI, contact: SereinContact) {
        self.contact = contact
        _api = ObservedObject(wrappedValue: api)
        _engine = StateObject(wrappedValue: SereinChatEngine(api: api, contact: contact))
    }

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                SereinStatusPill(title: securitySummary)
                Spacer()
                if !contact.isDeleted && !engine.archived { Button { showKeys = true } label: { Label("Security", systemImage: "lock.shield").font(.system(size: 12, weight: .semibold, relativeTo: .body)) } }
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(timeline) { item in
                            if item.startsNewDay { SereinConversationDaySeparator(timestamp: item.createdAt) }
                            if let event=item.eventText { SereinConversationSystemEvent(text:event,timestamp:item.createdAt) }
                            if let message=item.message {
                            HStack(alignment: .bottom, spacing: 7) {
                                if message.mine { Spacer(minLength: 34) }
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(message.text).font(.system(size: 15, relativeTo: .body)).textSelection(.enabled)
                                    if let attachment = message.attachment {
                                        HStack(spacing: 8) {
                                            Image(systemName: attachment.contentType.hasPrefix("audio/") ? "waveform" : attachment.contentType.hasPrefix("video/") ? "film" : "doc")
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text(attachment.filename).font(.system(size: 12, weight: .semibold, relativeTo: .body)).lineLimit(2)
                                                Text("\(attachment.contentType) · \(formatBytes(attachment.size))").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                                            }
                                            Spacer(minLength: 4)
                                            Button(engine.localFile(for: attachment) == nil ? "Download" : "Open") {
                                                if let local = engine.localFile(for: attachment) { fileToOpen = OpenAttachment(url: local, mimeType: attachment.contentType) }
                                                else { Task { if let saved = await engine.download(attachment) { fileToOpen = OpenAttachment(url: saved, mimeType: attachment.contentType) } } }
                                            }.buttonStyle(.bordered).font(.system(size: 10, weight: .semibold, relativeTo: .body))
                                        }.padding(9).background(Color.primary.opacity(colorScheme == .dark ? 0.08 : 0.035), in: RoundedRectangle(cornerRadius: 10))
                                    }
                                    Text(message.mine ? deliverySummary(message) : "\(message.sender) · \(formatMessageTime(message.createdAt))").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                                        .frame(maxWidth: .infinity, alignment: .trailing)
                                }
                                .padding(.horizontal, 12).padding(.vertical, 9)
                                .frame(maxWidth: UIScreen.main.bounds.width * 0.82, alignment: .leading)
                                .background(message.mine ? outgoingBubble : incomingBubble, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                                if !message.mine { Spacer(minLength: 34) }
                            }.id(item.id)
                            }
                        }
                    }.padding(.vertical, 8)
                }.onChange(of: engine.messages.count) { _ in if let last = engine.messages.last { proxy.scrollTo(last.id, anchor: .bottom) } }
            }.background(SereinConversationWallpaper())
            HStack(alignment: .bottom, spacing: 6) {
                Button { showEmojiPicker.toggle() } label: { Image(systemName: "face.smiling").font(.system(size: 19, relativeTo: .body)).frame(width: 36, height: 40) }
                    .buttonStyle(.bordered).accessibilityLabel("Choose an emoji").accessibilityHint("Insert an emoji or choose a GIF file").disabled(!engine.ready || contact.isDeleted || engine.archived)
                Button { showFilePicker = true } label: { Image(systemName: "paperclip").font(.system(size: 18, relativeTo: .body)).frame(width: 36, height: 40) }
                    .buttonStyle(.bordered).accessibilityLabel("Attach a file, GIF, or image").disabled(!engine.ready || contact.isDeleted || engine.archived)
                SereinEmojiComposer(text: $draft, isEnabled: engine.ready && !contact.isDeleted && !engine.archived, onPastedFile: sendPastedImage)
                    .frame(height: 40)
                Button { let value = draft; draft = ""; Task { await engine.sendText(value) } } label: { Image(systemName: "arrow.up.circle.fill").font(.system(size: 28, relativeTo: .body)) }
                    .disabled(!engine.ready || contact.isDeleted || engine.archived || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding()
        .overlay(alignment: .bottom) {
            if showEmojiPicker {
                VStack(alignment: .leading, spacing: 8) {
                    HStack { Text("Emojis").font(.system(size: 12, weight: .semibold, relativeTo: .body)); Spacer(); Button("Browse GIFs") { showGIFPicker = true }.font(.system(size: 11, weight: .semibold, relativeTo: .body)); Button("Attach file") { showFilePicker = true }.font(.system(size: 11, weight: .semibold, relativeTo: .body)) }
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 3), count: 8), spacing: 5) {
                        ForEach(Self.commonEmojis, id: \.self) { emoji in
                            Button { insertEmoji(emoji) } label: { Text(emoji).font(.system(size: 23)).frame(maxWidth: .infinity).frame(height: 34).contentShape(Rectangle()) }
                                .buttonStyle(.plain).accessibilityLabel("Insert \(emoji)")
                        }
                    }.frame(maxHeight: 128).clipped()
                    Text("GIFs and images use the encrypted attachment path.").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                }.padding(9).frame(maxWidth: .infinity).background(Color(uiColor: .secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12)).shadow(color: .black.opacity(0.18), radius: 12, y: 4).padding(.horizontal, 10).padding(.bottom, 54).transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeOut(duration: 0.18), value: showEmojiPicker)
        .navigationTitle(engine.peerDisplayName).navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button { showProfile = true } label: { Image(systemName: "info.circle") }.accessibilityLabel("Contact profile and shared media")
                if !contact.isDeleted && !engine.archived { Button { Task { do { try await engine.refreshPeerKeys() } catch { } } } label: { Image(systemName: "arrow.clockwise") }.accessibilityLabel("Refresh security details") }
            }
        }
        .sheet(isPresented: $showProfile) { SereinContactProfile(api: api, engine: engine, contact: contact, messages: engine.messages) }
        .sheet(isPresented: $showGIFPicker) { SereinNativeGIFPicker { url in Task { defer { try? FileManager.default.removeItem(at: url) }; await engine.sendFile(url: url, filename: url.lastPathComponent, contentType: "image/gif") } } }
        .task {
            if !engine.ready { await engine.initialize() }
            guard !contact.isDeleted && !engine.archived else { return }
            var cycles = 0
            while !Task.isCancelled && !engine.archived {
                await engine.poll(); cycles += 1
                if cycles % 12 == 0 { try? await engine.refreshPeerKeys() }
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
        .sheet(isPresented: $showKeys) {
            NavigationView {
                List {
                    Section { Text("Compare every full fingerprint with your contact through a separate trusted channel. A changed fingerprint is not trusted automatically.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                    Section("Contact devices") {
                        if engine.peerKeys.isEmpty { Text(engine.status).font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                        ForEach(engine.peerKeys) { peer in
                            VStack(alignment: .leading, spacing: 8) {
                                Text(peer.name).font(.system(size: 12, weight: .semibold, relativeTo: .body))
                                Text("Message capability: \(peer.ratchetVersion >= 3 ? "experimental ratchet v3" : "two-layer static v2")").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                                Text(peer.fingerprint.groupedFingerprint).font(.system(size: 10, design: .monospaced, relativeTo: .body)).textSelection(.enabled)
                                Text(peer.trusted ? "Verified on this iPhone" : (peer.previousFingerprint.isEmpty ? "Not verified" : (peer.previousFingerprint != peer.fingerprint ? "Key changed · verify again" : "Capability changed · verify again")))
                                    .font(.system(size: 10, relativeTo: .body)).foregroundStyle(peer.trusted ? SereinPalette.green : .orange)
                                if !peer.trusted { Button("I compared this fingerprint and capability") { pendingTrust = peer }.font(.system(size: 11, weight: .semibold, relativeTo: .body)) }
                            }.padding(.vertical, 4)
                        }
                    }
                }.listStyle(.insetGrouped).navigationTitle("E2EE device keys")
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showKeys = false } } }
            }
        }
        .alert(item: $pendingTrust) { peer in
            let changed = !peer.previousFingerprint.isEmpty && peer.previousFingerprint != peer.fingerprint
            let capabilityChanged = peer.previousRatchetVersion != peer.ratchetVersion
            return Alert(title: Text(changed ? "Device key changed" : (capabilityChanged ? "Message capability changed" : "Trust this device?")),
                         message: Text("Verify the complete fingerprint and reported capability with \(contact.display_name) through a separate trusted channel before continuing.\n\nCapability: \(peer.ratchetVersion >= 3 ? "experimental ratchet v3" : "two-layer static v2")\n\n\(peer.fingerprint.groupedFingerprint)" + (changed ? "\n\nPreviously trusted: \(peer.previousFingerprint.groupedFingerprint)" : "") + (capabilityChanged ? "\n\nRatchet capability changed from v\(peer.previousRatchetVersion) to v\(peer.ratchetVersion)." : "")),
                         primaryButton: .default(Text("Trust after comparison")) { do { try engine.trust(peer) } catch { } },
                         secondaryButton: .cancel())
        }
        .fileImporter(isPresented: $showFilePicker, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            let startedAccess = url.startAccessingSecurityScopedResource()
            let filename = url.lastPathComponent
            let mime = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
            Task { defer { if startedAccess { url.stopAccessingSecurityScopedResource() } }; await engine.sendFile(url: url, filename: filename, contentType: mime) }
        }
        .sheet(item: $fileToOpen) { item in SereinDocumentOpenSheet(url: item.url) { fileToOpen = nil } }
    }

    private static let commonEmojis = ["😀","😃","😄","😁","😆","😅","😂","🙂","🙃","😉","😊","😍","🥰","😘","😋","😎","🤔","🥳","😴","😭","😡","🤗","🤩","🤝","👋","🙌","👏","👍","👎","👌","✌️","🤞","🙏","💪","❤️","🧡","💛","💚","💙","💜","🖤","🤍","💔","💕","💖","💯","🔥","✨","🎉","🎂","☕","🍕","🌈","🌻","🐱","🐶","🦋","🌍","🚀","🎵"]
    private func insertEmoji(_ emoji: String) { draft.append(emoji) }
    private func sendPastedImage(_ url: URL) {
        let filename = url.lastPathComponent
        let mime = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? (url.pathExtension.lowercased() == "gif" ? "image/gif" : "application/octet-stream")
        Task { defer { try? FileManager.default.removeItem(at: url) }; await engine.sendFile(url: url, filename: filename, contentType: mime) }
    }

    private var timeline: [SereinConversationTimelineItem] {
        var items=engine.messages.map { SereinConversationTimelineItem(id:$0.id,createdAt:$0.createdAt,message:$0,eventText:nil) }
        let name=engine.peerDisplayName.replacingOccurrences(of:" (Deleted User)",with:"")
        if let connected=contact.connected_at { items.append(SereinConversationTimelineItem(id:"connection-event",createdAt:connected,message:nil,eventText:"You and \(name) are now friends.")) }
        if (contact.isDeleted || engine.archived),let deleted=engine.deletedAt ?? contact.deleted_at { items.append(SereinConversationTimelineItem(id:"deleted-event",createdAt:deleted,message:nil,eventText:"\(name) deleted his account. No new messages are allowed.")) }
        var previousDay=""
        return items.sorted { $0.createdAt == $1.createdAt ? $0.id < $1.id : $0.createdAt < $1.createdAt }.map { value in
            var row=value;let key=conversationDay(row.createdAt);row.startsNewDay=previousDay != key;previousDay=key;return row
        }
    }
    private func deliverySummary(_ message: SereinChatMessage) -> String {
        let label = message.readCount > 0 ? "Read" : (message.deliveredCount > 0 ? "Delivered" : (message.status == "pending" ? "Queued" : "Sent"))
        let counted = message.readCount > 0 ? message.readCount : message.deliveredCount
        let devices = message.recipientCount > 0 ? " · \(counted)/\(message.recipientCount) devices" : ""
        return "\(label)\(devices) · \(formatMessageTime(message.createdAt))"
    }
    private func conversationDay(_ timestamp: String) -> String { ISO8601DateFormatter().date(from: timestamp).map { Calendar.current.startOfDay(for: $0).formatted(.iso8601.year().month().day()) } ?? timestamp }
    private func formatMessageTime(_ timestamp: String) -> String { guard let date=ISO8601DateFormatter().date(from:timestamp) else { return timestamp };let f=DateFormatter();f.timeStyle = .short;return f.string(from:date) }
    private func formatBytes(_ size: Int64) -> String {
        if size < 1024 { return "\(size) B" }
        if size < 1024 * 1024 { return String(format: "%.1f KB", Double(size) / 1024) }
        return String(format: "%.1f MB", Double(size) / 1048576)
    }
}

private struct SereinEmojiComposer: UIViewRepresentable {
    @Binding var text: String
    let isEnabled: Bool
    let onPastedFile: (URL) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIView(context: Context) -> SereinGIFTextView {
        let view = SereinGIFTextView()
        view.delegate = context.coordinator
        view.onPastedFile = onPastedFile
        view.font = UIFont.preferredFont(forTextStyle: .body)
        view.textContainerInset = UIEdgeInsets(top: 8, left: 7, bottom: 8, right: 7)
        view.textContainer.lineFragmentPadding = 0
        view.layer.cornerRadius = 8
        view.layer.borderWidth = 0.7
        view.layer.borderColor = UIColor.separator.cgColor
        view.backgroundColor = .secondarySystemBackground
        view.isScrollEnabled = true
        view.accessibilityLabel = "Message, including emoji"
        view.accessibilityHint = "Emoji keyboard input is sent as text. Pasted GIFs and images are sent as encrypted attachments."
        return view
    }
    func updateUIView(_ view: SereinGIFTextView, context: Context) {
        context.coordinator.parent = self
        if view.text != text { view.text = text }
        view.isEditable = isEnabled
        view.isSelectable = true
        view.onPastedFile = onPastedFile
    }
    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: SereinEmojiComposer
        init(_ parent: SereinEmojiComposer) { self.parent = parent }
        func textViewDidChange(_ textView: UITextView) { parent.text = textView.text }
    }
}

private final class SereinGIFTextView: UITextView {
    var onPastedFile: ((URL) -> Void)?
    override func paste(_ sender: Any?) {
        let providers = UIPasteboard.general.itemProviders
        let gif = providers.first { $0.hasItemConformingToTypeIdentifier(UTType.gif.identifier) }
        let image = gif ?? providers.first { $0.hasItemConformingToTypeIdentifier(UTType.image.identifier) }
        guard let provider = image else { super.paste(sender); return }
        let type = gif != nil ? UTType.gif.identifier : UTType.image.identifier
        provider.loadFileRepresentation(forTypeIdentifier: type) { [weak self] source, _ in
            if let source {
                let ext = gif != nil ? "gif" : (source.pathExtension.isEmpty ? "png" : source.pathExtension)
                let staged = FileManager.default.temporaryDirectory.appendingPathComponent("serein-keyboard-\(UUID().uuidString).\(ext)")
                do {
                    try FileManager.default.copyItem(at: source, to: staged)
                    DispatchQueue.main.async { guard let self else { try? FileManager.default.removeItem(at: staged); return }; self.onPastedFile?(staged) }
                    return
                } catch { }
            }
            provider.loadDataRepresentation(forTypeIdentifier: type) { [weak self] data, _ in
                guard let data, data.count <= 64 * 1024 * 1024 else { return }
                let ext = gif != nil ? "gif" : "png"
                let staged = FileManager.default.temporaryDirectory.appendingPathComponent("serein-keyboard-\(UUID().uuidString).\(ext)")
                do {
                    try data.write(to: staged, options: .atomic)
                    DispatchQueue.main.async { guard let self else { try? FileManager.default.removeItem(at: staged); return }; self.onPastedFile?(staged) }
                } catch { }
            }
        }
    }
}

private struct OpenAttachment: Identifiable { let id = UUID(); let url: URL; let mimeType: String }

private struct SereinDocumentOpenSheet: UIViewControllerRepresentable {
    let url: URL
    let onDismiss: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(onDismiss: onDismiss) }
    func makeUIViewController(context: Context) -> Presenter {
        let presenter = Presenter(); presenter.onReady = { viewController in context.coordinator.open(url, from: viewController) }; return presenter
    }
    func updateUIViewController(_ uiViewController: Presenter, context: Context) { }

    final class Presenter: UIViewController {
        var onReady: ((UIViewController) -> Void)?
        override func viewDidAppear(_ animated: Bool) { super.viewDidAppear(animated); onReady?(self); onReady = nil }
    }
    final class Coordinator {
        private let onDismiss: () -> Void
        init(onDismiss: @escaping () -> Void) { self.onDismiss = onDismiss }
        func open(_ url: URL, from viewController: UIViewController) {
            do { try SereinAttachmentStore.shared.open(url, from: viewController, onDismiss: onDismiss) }
            catch { onDismiss() }
        }
    }
}

private extension String {
    var groupedFingerprint: String { stride(from: 0, to: count, by: 4).map { offset in let start = index(startIndex, offsetBy: offset); let end = index(start, offsetBy: min(4, count - offset)); return String(self[start..<end]) }.joined(separator: " ") }
}

private struct SereinNativeContacts: View {
    @ObservedObject var api: SereinAPI
    @State private var showAdd = false
    @State private var newIdentity = ""
    @State private var blockTarget: SereinContact?
    @State private var confirmBlock = false
    var body: some View {
        NavigationView {
            List {
                Section("Incoming requests") {
                    let incoming = api.contactRequests.filter { $0.direction == "incoming" }
                    if incoming.isEmpty { Text("No incoming requests.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                    ForEach(incoming) { request in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(request.display_name).font(.system(size: 12, weight: .semibold, relativeTo: .body))
                                Text("@\(request.username) · Received \(request.created_at)").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Accept") { Task { await api.acceptContactRequest(request) } }.font(.system(size: 10, weight: .semibold, relativeTo: .body))
                            Button("Decline", role: .destructive) { Task { await api.dismissContactRequest(request) } }.font(.system(size: 10, relativeTo: .body))
                        }
                    }
                }
                Section("Sent requests") {
                    let sent = api.contactRequests.filter { $0.direction == "sent" }
                    if sent.isEmpty { Text("No outgoing requests.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                    ForEach(sent) { request in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(request.display_name).font(.system(size: 12, weight: .semibold, relativeTo: .body))
                                Text("Request sent · awaiting acceptance · \(request.created_at)").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Cancel", role: .destructive) { Task { await api.dismissContactRequest(request) } }.font(.system(size: 10, relativeTo: .body))
                        }
                    }
                }
                Section("Contacts") {
                    ForEach(api.contacts) { contact in
                        HStack(spacing: 11) {
                            SereinAvatar(name: contact.display_name)
                            VStack(alignment: .leading) {
                                Text(contact.display_name).font(.system(size: 13, weight: .semibold, relativeTo: .body))
                                Text(contact.isDeleted ? "Deleted account · archived read-only chat" : "@\(contact.username) · \(contact.devices.count) device(s)").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                            }
                        }
                        .swipeActions { if !contact.isDeleted { Button("Remove", role: .destructive) { Task { await api.removeContact(contact) } }; Button("Block", role: .destructive) { blockTarget = contact; confirmBlock = true } } }
                    }
                }
            }
            .navigationTitle("Contacts")
            .toolbar { ToolbarItem(placement: .navigationBarLeading) { Button { Task { await api.refreshAccountData() } } label: { Image(systemName: "arrow.clockwise") } }; ToolbarItem(placement: .navigationBarTrailing) { Button { showAdd = true } label: { Image(systemName: "person.badge.plus") } } }
            .alert("Request a connection", isPresented: $showAdd) { TextField("Username or verified email", text: $newIdentity); Button("Cancel", role: .cancel) { }; Button("Send request") { Task { await api.addContact(identity: newIdentity); newIdentity = "" } } } message: { Text("The other person must accept. Sent and received requests show their timestamped pending status; acceptance creates a fresh conversation.") }
            .confirmationDialog("Block this account?", isPresented: $confirmBlock, titleVisibility: .visible) { if let target = blockTarget { Button("Block @\(target.username)", role: .destructive) { Task { await api.block(target) } } }; Button("Cancel", role: .cancel) { blockTarget = nil } } message: { Text("Blocking removes the contact link and prevents future requests and message delivery. Existing encrypted history remains stored.") }
        }
    }
}

private struct SereinNativeSettings: View {
    @ObservedObject var api: SereinAPI
    @Environment(\.scenePhase) private var scenePhase
    @State private var confirmRevokeOthers = false
    @State private var showConnectionSettings = false
    @State private var showDeleteAccount = false
    @State private var notificationStatus = "Checking notification permission…"
    @State private var notificationsAuthorized = false
    @State private var showingBackupExporter = false
    @State private var creatingBackup = false
    @State private var backupDocument = SereinBackupDocument(bytes: Data())
    @State private var backupFilename = "serein-backup.srbk"
    @State private var backupStatus = ""
    @AppStorage("serein.notifications.sound") private var notificationSound = true
    private var displayedAppVersion: String {
        let info = Bundle.main.infoDictionary ?? [:]
        return (info["SereinVersion"] as? String) ?? (info["CFBundleShortVersionString"] as? String) ?? "unknown"
    }
    var body: some View {
        NavigationView {
            List {
                Section("About") {
                    SereinDetailRow(title: "Version", value: displayedAppVersion)
                    Text("Current message encryption uses classical P-256 and AES-GCM; it is not post-quantum cryptography.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary)
                }
                Section("Account") { if let user = api.user { SereinDetailRow(title: "Name", value: user.display_name); SereinDetailRow(title: "Username", value: "@\(user.username)"); SereinDetailRow(title: "Email", value: user.email); SereinDetailRow(title: "Verification", value: user.email_verified ? "Verified" : "Not verified") } }
                Section("Connection") { SereinDetailRow(title: "Server origin", value: api.apiBase); SereinDetailRow(title: "Last checked", value: api.connectionTestedOrigin.isEmpty ? "Not checked" : api.connectionTestedOrigin); SereinDetailRow(title: "Status", value: api.connectionStatus); if !api.connectionDetails.isEmpty { Text(api.connectionDetails).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Button("Manage connection") { showConnectionSettings = true } }
                Section("Appearance") { Picker("Theme", selection: $api.theme) { Text("System").tag("system"); Text("Light").tag("light"); Text("Dark").tag("dark") }; Picker("Text size", selection: $api.fontScale) { Text("System default").tag("system"); Text("Large").tag("large"); Text("Extra large").tag("extra_large") }; Toggle("Reduce motion", isOn: $api.reduceMotion); Button("Save preferences") { Task { await api.savePreferences() } } }
                Section("Encrypted backups") {
                    Text("Export a timestamped encrypted .srbk snapshot to a location you choose in Files. New backups use an automatically generated random per-account key stored in the database, bound to the account ID and username, then wrapped to a one-use device key. The service can access it; no separate Replit secret is required. Messages and attachment references are included, but media bytes are not. Restore is only offered during initial authenticated setup; confirmed skip is final and no later Settings restore is available.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary)
                    Button(creatingBackup ? "Preparing encrypted backup…" : "Create encrypted backup") { createEncryptedBackup() }.disabled(creatingBackup || api.user == nil)
                    if !backupStatus.isEmpty { Text(backupStatus).font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                }
                Section("Notifications") {
                    Text("Permission is requested when you enable notifications. Serein can post a local notification when an open conversation syncs; background push delivery is not configured. Sound is a per-device preference and remains subject to iOS notification settings.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary)
                    Text(notificationStatus).font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary)
                    Button(api.notifications && notificationsAuthorized ? "Turn off notifications" : "Enable notifications") { Task { await toggleNotifications() } }
                    if notificationStatus.contains("Settings") { Button("Open iOS Settings") { if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) } } }
                    Toggle("Notification sound", isOn: $notificationSound).disabled(!api.notifications || !notificationsAuthorized)
                }
                Section("Privacy") { Picker("Online status", selection: $api.presenceVisibility) { Text("Contacts only").tag("contacts"); Text("Nobody").tag("nobody") }; Toggle("Allow contact requests", isOn: $api.allowContactRequests); Toggle("Find me by verified email", isOn: $api.discoverableByEmail); ForEach(api.blocks) { blocked in HStack { Text("@\(blocked.username)"); Spacer(); Button("Unblock") { Task { await api.unblock(blocked) } } } } }
                Section("Registered devices") {
                    ForEach(api.devices) { device in HStack { VStack(alignment: .leading, spacing: 3) { Text(device.name).font(.system(size: 12, weight: .semibold, relativeTo: .body)); Text(device.online == true ? "Online" : (device.last_seen_at ?? "Last active unavailable")).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Spacer(); if device.current == true { Text("THIS DEVICE").font(.system(size: 10, weight: .bold, relativeTo: .body)).foregroundStyle(SereinPalette.green) } else { Button("Revoke", role: .destructive) { Task { await api.revoke(device) } }.font(.system(size: 10, relativeTo: .body)) } } }
                    Button("Revoke other devices", role: .destructive) { confirmRevokeOthers = true }
                }
                Section("Security status") { Text("Web and native chat use separate Layer 1/Layer 2 per-device P-256 ECDH key pairs, HKDF-SHA256, and nested AES-GCM after combined local fingerprint verification. Native private keys use Secure Enclave when available and otherwise Keychain-protected CryptoKit keys; local history uses a device-only Keychain key. Capability-3 messages use an experimental symmetric ratchet with static P-256 bootstrap; there are no DH ratchet turns or forward secrecy. This implementation has not been independently reviewed and does not provide automatic key rotation/recovery or background message delivery. Use test data only.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary); Text("Email verification requires a configured server provider. Account recovery is not configured.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                Section("Danger zone") { Text("Account deletion removes server records, sessions, device keys, and this iPhone’s account-scoped local history. Contacts retain a read-only archived chat. Legacy downloads in shared Serein/Downloads cannot yet be attributed to this account and may remain; newer downloads are account-scoped.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary); Button("Permanently delete account", role: .destructive) { showDeleteAccount = true }.sheet(isPresented: $showDeleteAccount) { SereinDeleteAccountSheet(api: api) } }
                Section { Button("Sign out", role: .destructive) { Task { _ = await api.signOut() } } }
            }.listStyle(.insetGrouped).navigationTitle("Settings")
                .task { await api.refreshAccountData(); await refreshNotificationStatus() }
                .onChange(of: scenePhase) { phase in if phase == .active { Task { await refreshNotificationStatus() } } }
                .confirmationDialog("Revoke other devices? Their local data cannot be remotely erased.", isPresented: $confirmRevokeOthers, titleVisibility: .visible) { Button("Revoke devices", role: .destructive) { Task { await api.revokeOthers() } } }
                .sheet(isPresented: $showConnectionSettings) { SereinConnectionSettings(api: api) }
                .fileExporter(isPresented: $showingBackupExporter, document: backupDocument, contentType: .data, defaultFilename: backupFilename) { result in
                    creatingBackup = false
                    backupDocument = SereinBackupDocument(bytes: Data())
                    switch result {
                    case .success: backupStatus = "Encrypted snapshot saved. Keep the file somewhere safe; media files were not packaged."; if scenePhase != .active { Task { await postBackupNotification("Encrypted backup saved", "The encrypted Serein backup was saved to Files.") } }
                    case .failure(let error): backupStatus = "Backup export did not complete: \\(error.localizedDescription)"; if scenePhase != .active { Task { await postBackupNotification("Backup export did not complete", "Return to Serein for details and try saving again.") } }
                    }
                }
        }
        .onChange(of: api.theme) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.fontScale) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.reduceMotion) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.presenceVisibility) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.allowContactRequests) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.discoverableByEmail) { _ in Task { await api.savePreferences() } }
    }
    @MainActor private func createEncryptedBackup() {
        guard let user = api.user else { backupStatus = "Sign in before creating a backup."; return }
        do {
            let local = try SereinLocalStore(accountID: user.id)
            let messages = local.backupMessages()
            guard messages.count <= SereinBackupStore.maximumMessages else { throw SereinBackupStore.BackupError.tooLarge }
            let contactRows: [[String: Any]] = api.contacts.filter { !$0.isDeleted }.map { ["user_id": $0.user_id, "username": $0.username, "display_name": $0.display_name] }
            let snapshot: [String: Any] = ["snapshot_version": 1, "created_at": ISO8601DateFormatter().string(from: Date()), "messages": messages, "contacts": contactRows, "media": ["included": false, "policy": "references-only"]]
            creatingBackup = true; backupStatus = "Step 1 of 3 · Requesting the account-bound backup key… Keep Serein open until encryption starts."
            let backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "SereinEncryptedBackup") { DispatchQueue.main.async { self.backupStatus = "Backup is still being prepared; return to Serein to continue." } }
            Task {
                var keyBytes = Data()
                defer { if !keyBytes.isEmpty { keyBytes.resetBytes(in: 0..<keyBytes.count) }; if backgroundTask != .invalid { UIApplication.shared.endBackgroundTask(backgroundTask) } }
                do {
                    keyBytes = try await api.requestBackupKey(accountID: user.id, username: user.username)
                    backupStatus = "Step 2 of 3 · Compressing and encrypting locally…"
                    let keyForCodec = keyBytes
                    let result = try await Task.detached(priority: .userInitiated) {
                        try SereinBackupStore.create(accountID: user.id, username: user.username, backupKey: keyForCodec, snapshot: snapshot)
                    }.value
                    guard api.user?.id == user.id else { creatingBackup = false; backupStatus = "Account changed before export completed. Try again while signed in."; await postBackupNotification("Backup not completed", "The signed-in account changed before export completed."); return }
                    backupDocument = SereinBackupDocument(bytes: result.bytes)
                    backupFilename = result.filename
                    backupStatus = "Step 3 of 3 · Encrypted file ready. Choose a durable location in Files."
                    showingBackupExporter = true
                    if scenePhase != .active { await postBackupNotification("Encrypted backup ready", "Return to Serein and choose where to save the encrypted file.") }
                } catch { creatingBackup = false; backupStatus = error.localizedDescription; await postBackupNotification("Backup could not be completed", "Serein could not prepare the encrypted backup. Return to the app for details.") }
            }
        } catch { backupStatus = error.localizedDescription }
    }

    @MainActor private func postBackupNotification(_ title:String,_ body:String) async {
        guard api.notifications else { return }
        let center=UNUserNotificationCenter.current(),settings=await center.notificationSettings()
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional || settings.authorizationStatus == .ephemeral else { return }
        let content=UNMutableNotificationContent();content.title=title;content.body=body;content.sound=nil
        let request=UNNotificationRequest(identifier:"serein-backup-\(UUID().uuidString)",content:content,trigger:nil)
        try? await center.add(request)
    }
    private func refreshNotificationStatus() async {
        let status = await api.notificationAuthorizationStatus()
        switch status {
        case .authorized, .provisional, .ephemeral: notificationsAuthorized = true; notificationStatus = api.notifications ? "Permission allowed · notifications enabled" : "Permission allowed · notifications currently off"
        case .denied: notificationsAuthorized = false; notificationStatus = "Permission denied · open iOS Settings to allow notifications"
        case .notDetermined: notificationsAuthorized = false; notificationStatus = "Not requested yet · tap Enable notifications to ask iOS"
        @unknown default: notificationsAuthorized = false; notificationStatus = "Notification permission status is unavailable"
        }
    }
    private func toggleNotifications() async {
        if api.notifications && notificationsAuthorized {
            _ = await api.setNotificationsEnabled(false)
            await refreshNotificationStatus()
            return
        }
        let result = await api.setNotificationsEnabled(true)
        if !result {
            let current = await api.notificationAuthorizationStatus()
            notificationStatus = current == .denied ? "Permission denied · open iOS Settings to allow notifications" : "Permission was not granted; no notifications will be posted"
        } else { notificationStatus = "Permission allowed · notifications enabled" }
    }
}

private struct SereinDeleteAccountSheet: View {
    @ObservedObject var api: SereinAPI
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var phrase = ""
    @State private var deleting = false
    @State private var error = ""
    var body: some View {
        NavigationView {
            Form {
                Section("Permanent deletion") {
                    Text("This removes the account, server-side data, credentials, device keys and sessions. Contacts retain a read-only archived conversation; the username may later be registered as a new identity.")
                    Text("Legacy downloaded attachments in shared Serein/Downloads may remain because they have no account label; newer downloads are account-scoped.").foregroundStyle(.secondary)
                }
                Section("Confirm") {
                    SecureField("Current password", text: $password).textContentType(.password)
                    TextField("Type DELETE", text: $phrase).textInputAutocapitalization(.characters).autocorrectionDisabled()
                }
                if !error.isEmpty { Section { Text(error).foregroundStyle(.red) } }
            }
            .navigationTitle("Delete account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(deleting) }
                ToolbarItem(placement: .confirmationAction) {
                    Button(deleting ? "Deleting…" : "Delete", role: .destructive) {
                        guard phrase == "DELETE", !password.isEmpty else { error = "Enter your current password and type DELETE exactly."; return }
                        deleting = true
                        let secret = password; password = ""
                        Task {
                            let result = await api.deleteAccount(password: secret)
                            deleting = false
                            if result.deleted {
                                UserDefaults.standard.removeObject(forKey: "serein.restore-prompt-done")
                                dismiss()
                                if !result.localDataCleared { api.errorMessage = "Account deleted and sessions revoked, but some local history or keys could not be cleared. Remove Serein app data from this device." }
                            } else { error = result.error ?? "Account deletion could not be completed." }
                            password = ""
                        }
                    }.disabled(deleting || phrase != "DELETE" || password.isEmpty)
                }
            }
        }
    }
}

private struct SereinConnectionSettings: View {
    @ObservedObject var api: SereinAPI
    @Environment(\.dismiss) private var dismiss
    @State private var serverOrigin = ""
    @State private var checking = false
    @State private var showSwitchConfirmation = false
    @State private var pendingOrigin = ""
    @State private var localMessage = ""
    var body: some View {
        NavigationView {
            Form {
                Section("Server") {
                    TextField("https://serein.example.com", text: $serverOrigin).textInputAutocapitalization(.never).keyboardType(.URL).autocorrectionDisabled()
                    Text("Enter only the HTTPS origin; paths, credentials, and query values are not accepted. Self-hosted servers are supported.").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary)
                    Button { Task { checking = true; localMessage = ""; _ = await api.testServerConnection(serverOrigin); checking = false } } label: { HStack { if checking { ProgressView() }; Text(checking ? "Checking…" : "Check connection") } }.disabled(checking || serverOrigin.isEmpty)
                    Text(api.connectionStatus).font(.system(size: 12, weight: .semibold, relativeTo: .body))
                    if !api.connectionDetails.isEmpty { Text(api.connectionDetails).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }
                    if !localMessage.isEmpty { Text(localMessage).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.red) }
                }
                Section { Button("Save server") { saveServer() }.disabled(checking) }
            }
            .navigationTitle("Connection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
            .confirmationDialog("Switch servers? You will be signed out of the current server.", isPresented: $showSwitchConfirmation, titleVisibility: .visible) {
                Button("Sign out and switch", role: .destructive) { Task { let revoked = await api.signOut(); guard revoked else { localMessage = "Could not confirm sign-out from the current server. The local session was cleared; the connection was not changed."; return }; do { try api.setServerOrigin(pendingOrigin); dismiss() } catch { localMessage = error.localizedDescription } } }
                Button("Cancel", role: .cancel) { }
            }
            .onAppear { serverOrigin = api.apiBase }
            .onChange(of: serverOrigin) { _ in localMessage = "" }
        }
    }
    private func normalizedInput() -> String? {
        guard let components = URLComponents(string: serverOrigin.trimmingCharacters(in: .whitespacesAndNewlines)), components.scheme?.lowercased() == "https", let host = components.host, !host.isEmpty, components.user == nil, components.password == nil, components.path.isEmpty || components.path == "/", components.query == nil, components.fragment == nil else { return nil }
        return "https://\(host)" + (components.port.map { ":\($0)" } ?? "")
    }
    private func saveServer() {
        guard let normalized = normalizedInput() else { localMessage = "Use an HTTPS server origin without a path, credentials, or query values."; return }
        guard api.connectionTestedOrigin == normalized else { localMessage = "Check this server successfully before saving it."; return }
        if api.signedIn && normalized != api.apiBase { pendingOrigin = normalized; showSwitchConfirmation = true; return }
        do { try api.setServerOrigin(normalized); dismiss() } catch { localMessage = error.localizedDescription }
    }
}

private struct SereinDetailRow: View {
    let title: String
    let value: String
    var body: some View { HStack { Text(title).foregroundStyle(.secondary); Spacer(); Text(value).multilineTextAlignment(.trailing) }.font(.system(size: 12, relativeTo: .body)) }
}
