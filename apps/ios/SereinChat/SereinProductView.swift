import SwiftUI
import UIKit
import AVFoundation
import UniformTypeIdentifiers

struct SereinProductRootView: View {
    @StateObject private var api = SereinAPI()
    @Environment(\.dynamicTypeSize) private var systemDynamicTypeSize
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
        let minimum: DynamicTypeSize = api.fontScale == "extra_large" ? .xxxLarge : .xLarge
        guard api.fontScale != "system" else { return systemDynamicTypeSize }
        return systemDynamicTypeSize < minimum ? minimum : systemDynamicTypeSize
    }
    var body: some View {
        Group {
            if api.signedIn { SereinProductTabs(api: api) }
            else { SereinNativeAuthView(api: api) }
        }
        .tint(SereinPalette.green)
        .environment(\.dynamicTypeSize, effectiveDynamicTypeSize)
        .onChange(of: api.errorMessage) { value in showingError = value != nil }
        .onChange(of: api.theme) { value in theme = value }
        .alert("Serein", isPresented: $showingError) {
            Button("OK", role: .cancel) { api.errorMessage = nil }
        } message: { Text(api.errorMessage ?? "") }
        .onAppear { if lastWhatsNewVersion != displayedAppVersion { showingWhatsNew = true } }
        .sheet(isPresented: $showingWhatsNew) { SereinWhatsNewView(version: displayedAppVersion, isFirstInstall: lastWhatsNewVersion.isEmpty) { lastWhatsNewVersion = displayedAppVersion; showingWhatsNew = false } }
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
                    VStack(alignment: .leading, spacing: 7) { SereinSectionLabel(title: api.verificationRequired ? "EMAIL VERIFICATION" : "ACCOUNT"); Text(api.verificationRequired ? "Verify your email" : (registering ? "Create your account" : "Welcome back")).font(.system(size: 29, weight: .bold, design: .rounded, relativeTo: .body)); Text(api.verificationRequired ? "Enter the six-digit code sent to your inbox." : "Connect to your Serein API over HTTPS.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary) }
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
                                        HStack { Spacer(); if verifyingOtp || api.busy { ProgressView().tint(.white) }; Text(verifyingOtp || api.busy ? "Verifying…" : (otpDigits.joined().count == 6 ? "Verify email" : "Enter the six-digit code")); Spacer(); if !(verifyingOtp || api.busy) { Image(systemName: "arrow.right") } }
                                    }.buttonStyle(SereinPrimaryButtonStyle()).disabled(api.busy || verifyingOtp || api.verificationEmail.isEmpty || otpDigits.joined().count != 6)
                                    HStack {
                                        Button(resendButtonTitle) { Task { if let seconds = await api.resendVerification(identity: api.verificationEmail) { startResendCooldown(seconds) } } }.disabled(api.busy || verifyingOtp || resendSeconds > 0 || api.verificationEmail.isEmpty)
                                        Spacer()
                                        Button("← Back to sign in") { api.verificationRequired = false; api.verificationEmail = ""; api.verificationIdentity = ""; registering = false; resendSeconds = 0; otpDigits = Array(repeating: "", count: 6) }.font(.system(size: 11, weight: .medium, relativeTo: .body))
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
            SereinNativeCalls().tabItem { Label("Calls", systemImage: "phone") }
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
                    List(api.contacts) { contact in NavigationLink(destination: SereinNativeConversation(api: api, contact: contact)) { HStack(spacing: 11) { SereinAvatar(name: contact.display_name, size: 42); VStack(alignment: .leading, spacing: 3) { Text(contact.display_name).font(.system(size: 13, weight: .semibold, relativeTo: .body)); Text("@\(contact.username) · \(contact.online ? "Online" : "Offline")").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Spacer(); Text("\(contact.devices.count) devices").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.tertiary) } } }
                        .listStyle(.insetGrouped)
                }
            }.navigationTitle("Chats").toolbar { ToolbarItem(placement: .navigationBarTrailing) { Button { Task { await api.refreshAccountData() } } label: { Image(systemName: "arrow.clockwise") } } }
        }
    }
}

private struct SereinNativeConversation: View {
    let contact: SereinContact
    @StateObject private var engine: SereinChatEngine
    @State private var draft = ""
    @State private var showKeys = false
    @State private var showFilePicker = false
    @State private var pendingTrust: SereinPeerKey?
    @State private var fileToOpen: OpenAttachment?

    init(api: SereinAPI, contact: SereinContact) {
        self.contact = contact
        _engine = StateObject(wrappedValue: SereinChatEngine(api: api, contact: contact))
    }

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                SereinStatusPill(title: "\(engine.activeDevices.count) active device(s) · \(contact.online ? "online" : "offline")")
                Spacer()
                Button { showKeys = true } label: { Label("Keys", systemImage: "key.horizontal").font(.system(size: 11, weight: .semibold, relativeTo: .body)) }
            }
            Text(engine.status).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(engine.messages) { message in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(message.text).font(.system(size: 14, relativeTo: .body)).textSelection(.enabled)
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
                                    }.padding(9).background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                                }
                                Text("\(message.mine ? "You" : message.sender) · \(message.status)").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.tertiary)
                            }.padding(11).frame(maxWidth: .infinity, alignment: .leading)
                                .background(message.mine ? SereinPalette.paleMint.opacity(0.7) : Color(uiColor: .secondarySystemBackground), in: RoundedRectangle(cornerRadius: 13))
                                .id(message.id)
                        }
                    }.padding(.vertical, 8)
                }.onChange(of: engine.messages.count) { _ in if let last = engine.messages.last { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
            HStack(alignment: .bottom, spacing: 8) {
                Button { showFilePicker = true } label: { Image(systemName: "paperclip").font(.system(size: 19, relativeTo: .body)).frame(width: 38, height: 40) }
                    .buttonStyle(.bordered).disabled(!engine.ready)
                TextField("Write an encrypted message…", text: $draft).textFieldStyle(.roundedBorder).disabled(!engine.ready)
                Button { let value = draft; draft = ""; Task { await engine.sendText(value) } } label: { Image(systemName: "arrow.up.circle.fill").font(.system(size: 28, relativeTo: .body)) }
                    .disabled(!engine.ready || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding()
        .navigationTitle(contact.display_name).navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .navigationBarTrailing) { Button { Task { do { try await engine.refreshPeerKeys() } catch { } } } label: { Image(systemName: "arrow.clockwise") } } }
        .task {
            if !engine.ready { await engine.initialize() }
            var cycles = 0
            while !Task.isCancelled {
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
                                Text(peer.fingerprint.groupedFingerprint).font(.system(size: 10, design: .monospaced, relativeTo: .body)).textSelection(.enabled)
                                Text(peer.trusted ? "Verified on this iPhone" : (peer.previousFingerprint.isEmpty ? "Not verified" : "Key changed · verify again"))
                                    .font(.system(size: 10, relativeTo: .body)).foregroundStyle(peer.trusted ? SereinPalette.green : .orange)
                                if !peer.trusted { Button("I compared this fingerprint") { pendingTrust = peer }.font(.system(size: 11, weight: .semibold, relativeTo: .body)) }
                            }.padding(.vertical, 4)
                        }
                    }
                }.listStyle(.insetGrouped).navigationTitle("E2EE device keys")
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showKeys = false } } }
            }
        }
        .alert(item: $pendingTrust) { peer in
            let changed = !peer.previousFingerprint.isEmpty && peer.previousFingerprint != peer.fingerprint
            return Alert(title: Text(changed ? "Device key changed" : "Trust this device?"),
                         message: Text("Verify this complete fingerprint with \(contact.display_name) through a separate trusted channel before continuing.\n\n\(peer.fingerprint.groupedFingerprint)" + (changed ? "\n\nPreviously trusted: \(peer.previousFingerprint.groupedFingerprint)" : "")),
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

    private func formatBytes(_ size: Int64) -> String {
        if size < 1024 { return "\(size) B" }
        if size < 1024 * 1024 { return String(format: "%.1f KB", Double(size) / 1024) }
        return String(format: "%.1f MB", Double(size) / 1048576)
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
                    if incoming.isEmpty { Text("No pending requests.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                    ForEach(incoming) { request in HStack { VStack(alignment: .leading) { Text(request.display_name).font(.system(size: 12, weight: .semibold, relativeTo: .body)); Text("@\(request.username)").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Spacer(); Button("Accept") { Task { await api.acceptContactRequest(request) } }.font(.system(size: 10, weight: .semibold, relativeTo: .body)); Button("Decline", role: .destructive) { Task { await api.dismissContactRequest(request) } }.font(.system(size: 10, relativeTo: .body)) } }
                }
                Section("Contacts") {
                    ForEach(api.contacts) { contact in HStack(spacing: 11) { SereinAvatar(name: contact.display_name); VStack(alignment: .leading) { Text(contact.display_name).font(.system(size: 13, weight: .semibold, relativeTo: .body)); Text("@\(contact.username) · \(contact.devices.count) device(s)").font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) } }.swipeActions { Button("Remove", role: .destructive) { Task { await api.removeContact(contact) } }; Button("Block", role: .destructive) { blockTarget = contact; confirmBlock = true } }
                }
            }
            .navigationTitle("Contacts")
            .toolbar { ToolbarItem(placement: .navigationBarLeading) { Button { Task { await api.refreshAccountData() } } label: { Image(systemName: "arrow.clockwise") } }; ToolbarItem(placement: .navigationBarTrailing) { Button { showAdd = true } label: { Image(systemName: "person.badge.plus") } } }
            .alert("Request a connection", isPresented: $showAdd) { TextField("Username or verified email", text: $newIdentity); Button("Cancel", role: .cancel) { }; Button("Send request") { Task { await api.addContact(identity: newIdentity); newIdentity = "" } } } message: { Text("The other person must accept. The server response does not reveal whether an account matched.") }
            .confirmationDialog("Block this account?", isPresented: $confirmBlock, titleVisibility: .visible) { if let target = blockTarget { Button("Block @\(target.username)", role: .destructive) { Task { await api.block(target) } } }; Button("Cancel", role: .cancel) { blockTarget = nil } } message: { Text("Blocking removes the contact link and prevents future requests and message delivery. Existing encrypted history remains stored.") }
        }
    }
}

private struct SereinNativeCalls: View {
    @State private var pendingVideo: Bool?
    @State private var showPermissionDialog = false
    @State private var permissionDenied = false
    @State private var permissionStatus = "No call was started"
    private var permissionExplanation: String {
        pendingVideo == true ? "Serein needs microphone and camera access to prepare a video call. Permission is required before any call can begin." : "Serein needs microphone access to prepare an audio call. Permission is required before any call can begin."
    }
    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                Image(systemName: pendingVideo == true ? "video" : "waveform.path").font(.system(size: 38, relativeTo: .body)).foregroundStyle(SereinPalette.green)
                Text(pendingVideo == nil ? "Private calling setup" : "Preparing \(pendingVideo == true ? "video" : "audio") call").font(.system(size: 20, weight: .bold, relativeTo: .body))
                Text("Microphone is required for audio; microphone and camera are required for video. Permission checks do not place a call. Encrypted QUIC media transport and signaling are not integrated, so no remote call will be started.").font(.system(size: 12, relativeTo: .body)).foregroundStyle(.secondary).multilineTextAlignment(.center)
                if pendingVideo == nil {
                    Button { pendingVideo = false; permissionDenied = false; showPermissionDialog = true } label: { Label("Start audio call", systemImage: "phone.fill").frame(maxWidth: .infinity) }.buttonStyle(.borderedProminent)
                    Button { pendingVideo = true; permissionDenied = false; showPermissionDialog = true } label: { Label("Start video call", systemImage: "video.fill").frame(maxWidth: .infinity) }.buttonStyle(.bordered)
                } else {
                    SereinStatusPill(title: permissionStatus)
                    Button("Retry permission check") { requestCallPermissions() }.buttonStyle(.borderedProminent)
                    Button("Cancel setup", role: .cancel) { pendingVideo = nil; permissionStatus = "No call was started" }.buttonStyle(.bordered)
                }
                Spacer(minLength: 0)
            }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity).background(Color(uiColor: .systemGroupedBackground)).navigationTitle("Calls")
                .alert(permissionDenied ? "Call permission required" : "Permissions before calling", isPresented: $showPermissionDialog) {
                    Button("Retry") { requestCallPermissions() }
                    Button("Open Settings") { if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) } }
                    Button("Cancel", role: .cancel) { pendingVideo = nil; permissionStatus = "No call was started" }
                } message: { Text(permissionDenied ? "Access is denied or blocked. Retry the system permission request, or enable the required access in iOS Settings. No call has started." : permissionExplanation) }
        }
    }
    private func requestCallPermissions() {
        guard let video = pendingVideo else { return }
        permissionStatus = "Checking permissions…"
        AVAudioSession.sharedInstance().requestRecordPermission { microphoneGranted in
            guard microphoneGranted else { DispatchQueue.main.async { permissionDenied = true; permissionStatus = "Microphone permission denied"; showPermissionDialog = true }; return }
            if video {
                AVCaptureDevice.requestAccess(for: .video) { cameraGranted in
                    DispatchQueue.main.async { permissionDenied = !cameraGranted; permissionStatus = cameraGranted ? "Permissions granted · no call connected" : "Camera permission denied"; showPermissionDialog = !cameraGranted }
                }
            } else {
                DispatchQueue.main.async { permissionDenied = false; permissionStatus = "Microphone permission granted · no call connected" }
            }
        }
    }
}

private struct SereinNativeSettings: View {
    @ObservedObject var api: SereinAPI
    @State private var confirmRevokeOthers = false
    @State private var showConnectionSettings = false
    var body: some View {
        NavigationView {
            List {
                Section("Account") { if let user = api.user { SereinDetailRow(title: "Name", value: user.display_name); SereinDetailRow(title: "Username", value: "@\(user.username)"); SereinDetailRow(title: "Email", value: user.email); SereinDetailRow(title: "Verification", value: user.email_verified ? "Verified" : "Not verified") } }
                Section("Connection") { SereinDetailRow(title: "Server origin", value: api.apiBase); SereinDetailRow(title: "Last checked", value: api.connectionTestedOrigin.isEmpty ? "Not checked" : api.connectionTestedOrigin); SereinDetailRow(title: "Status", value: api.connectionStatus); if !api.connectionDetails.isEmpty { Text(api.connectionDetails).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Button("Manage connection") { showConnectionSettings = true } }
                Section("Appearance") { Picker("Theme", selection: $api.theme) { Text("System").tag("system"); Text("Light").tag("light"); Text("Dark").tag("dark") }; Picker("Text size", selection: $api.fontScale) { Text("System default").tag("system"); Text("Large").tag("large"); Text("Extra large").tag("extra_large") }; Toggle("Reduce motion", isOn: $api.reduceMotion); Toggle("Notifications preference", isOn: $api.notifications); Button("Save preferences") { Task { await api.savePreferences() } } }
                Section("Privacy") { Picker("Online status", selection: $api.presenceVisibility) { Text("Contacts only").tag("contacts"); Text("Nobody").tag("nobody") }; Toggle("Allow contact requests", isOn: $api.allowContactRequests); Toggle("Find me by verified email", isOn: $api.discoverableByEmail); ForEach(api.blocks) { blocked in HStack { Text("@\(blocked.username)"); Spacer(); Button("Unblock") { Task { await api.unblock(blocked) } } } } }
                Section("Registered devices") {
                    ForEach(api.devices) { device in HStack { VStack(alignment: .leading, spacing: 3) { Text(device.name).font(.system(size: 12, weight: .semibold, relativeTo: .body)); Text(device.online == true ? "Online" : (device.last_seen_at ?? "Last active unavailable")).font(.system(size: 10, relativeTo: .body)).foregroundStyle(.secondary) }; Spacer(); if device.current == true { Text("THIS DEVICE").font(.system(size: 10, weight: .bold, relativeTo: .body)).foregroundStyle(SereinPalette.green) } else { Button("Revoke", role: .destructive) { Task { await api.revoke(device) } }.font(.system(size: 10, relativeTo: .body)) } } }
                    Button("Revoke other devices", role: .destructive) { confirmRevokeOthers = true }
                }
                Section("Security status") { Text("Web and native chat use per-device P-256 ECDH, HKDF-SHA256, and AES-GCM after explicit local fingerprint verification. Native private keys use Secure Enclave when available and otherwise Keychain-protected CryptoKit keys; local history uses a device-only Keychain key. This implementation has not been independently reviewed and does not provide forward secrecy, automatic key rotation/recovery, or background message delivery. Use test data only.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary); Text("Email verification requires a configured server provider. Account recovery and calls are not configured.").font(.system(size: 11, relativeTo: .body)).foregroundStyle(.secondary) }
                Section { Button("Sign out", role: .destructive) { Task { _ = await api.signOut() } } }
            }.listStyle(.insetGrouped).navigationTitle("Settings")
                .task { await api.refreshAccountData() }
                .confirmationDialog("Revoke other devices? Their local data cannot be remotely erased.", isPresented: $confirmRevokeOthers, titleVisibility: .visible) { Button("Revoke devices", role: .destructive) { Task { await api.revokeOthers() } } }
                .sheet(isPresented: $showConnectionSettings) { SereinConnectionSettings(api: api) }
        }
        .onChange(of: api.theme) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.fontScale) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.reduceMotion) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.notifications) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.presenceVisibility) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.allowContactRequests) { _ in Task { await api.savePreferences() } }
        .onChange(of: api.discoverableByEmail) { _ in Task { await api.savePreferences() } }
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
