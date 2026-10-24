import SwiftUI

struct SereinProductRootView: View {
    @StateObject private var api = SereinAPI()
    @AppStorage("serein.theme") private var theme = "system"
    @State private var showingError = false
    var body: some View {
        Group {
            if api.signedIn { SereinProductTabs(api: api) }
            else { SereinNativeAuthView(api: api) }
        }
        .tint(SereinPalette.green)
        .onChange(of: api.errorMessage) { value in showingError = value != nil }
        .onChange(of: api.theme) { value in theme = value }
        .alert("Serein", isPresented: $showingError) {
            Button("OK", role: .cancel) { api.errorMessage = nil }
        } message: { Text(api.errorMessage ?? "") }
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
    @State private var otpCode = ""
    var body: some View {
        ZStack {
            LinearGradient(colors: [Color(uiColor: .systemBackground), SereinPalette.paleMint.opacity(0.45)], startPoint: .topLeading, endPoint: .bottomTrailing).ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack { SereinAvatar(name: "Serein", size: 42); VStack(alignment: .leading) { Text("Serein").font(.system(size: 20, weight: .bold, design: .rounded)); Text("SEREIN ACCOUNT").font(.system(size: 8, weight: .bold)).tracking(1.1).foregroundStyle(.secondary) }; Spacer() }
                    VStack(alignment: .leading, spacing: 7) { SereinSectionLabel(title: "ACCOUNT"); Text(registering ? "Create your account" : "Welcome back").font(.system(size: 29, weight: .bold, design: .rounded)); Text("Connect to your Serein API over HTTPS.").font(.system(size: 12)).foregroundStyle(.secondary) }
                    SereinCard {
                        VStack(spacing: 13) {
                            TextField("https://api.your-domain.example", text: $api.apiBase).textInputAutocapitalization(.never).keyboardType(.URL).autocorrectionDisabled().padding(12).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
                            if api.verificationRequired {
                                VStack(spacing: 13) {
                                    Text("Verify your email").font(.system(size: 20, weight: .bold, design: .rounded)).frame(maxWidth: .infinity, alignment: .leading)
                                    Text("Enter the six-digit code emailed to your account. Codes expire after ten minutes.").font(.system(size: 11)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                                    input("Email address", text: $api.verificationEmail, icon: "envelope")
                                    HStack { Image(systemName: "number").foregroundStyle(.secondary); TextField("Six-digit code", text: $otpCode).keyboardType(.numberPad).textContentType(.oneTimeCode).textInputAutocapitalization(.never) }.padding(12).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
                                    Button { Task { await api.verifyEmail(code: otpCode, email: api.verificationEmail) } } label: { HStack { Spacer(); Text(api.busy ? "Verifying…" : "Verify email"); Spacer(); Image(systemName: "arrow.right") } }.buttonStyle(SereinPrimaryButtonStyle()).disabled(api.busy || api.verificationEmail.isEmpty || otpCode.count != 6)
                                    input("Account email or username", text: $api.verificationIdentity, icon: "person")
                                    Button("Resend verification code") { Task { await api.resendVerification(identity: api.verificationIdentity) } }.disabled(api.busy || api.verificationIdentity.isEmpty)
                                    Button("Back to sign in") { api.verificationRequired = false; registering = false; otpCode = "" }.font(.system(size: 12))
                                }
                            } else {
                                HStack(spacing: 6) { modeButton("Sign in", active: !registering) { withAnimation(.easeInOut(duration: 0.2)) { registering = false } }; modeButton("Create account", active: registering) { withAnimation(.easeInOut(duration: 0.2)) { registering = true } } }
                                if registering {
                                    input("Display name", text: $displayName, icon: "person")
                                    input("Username", text: $username, icon: "at")
                                    input("Email", text: $email, icon: "envelope")
                                } else { input("Username or email", text: $username, icon: "person") }
                                HStack { Image(systemName: "lock").foregroundStyle(.secondary); Group { if passwordVisible { TextField("Password", text: $password) } else { SecureField("Password", text: $password) } }.textInputAutocapitalization(.never).autocorrectionDisabled(); Button { passwordVisible.toggle() } label: { Image(systemName: passwordVisible ? "eye.slash" : "eye") }.accessibilityLabel(passwordVisible ? "Hide password" : "Show password") }.padding(12).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
                                if registering {
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text("Password requirements").font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                                        requirement("At least 8 characters", met: password.unicodeScalars.count >= 8)
                                        requirement("No more than 1024 UTF-8 bytes", met: password.utf8.count <= 1024)
                                    }.padding(11).frame(maxWidth: .infinity, alignment: .leading).background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10)).transition(.opacity.combined(with: .move(edge: .top)))
                                    Text("New accounts must verify their email before signing in. A code is sent by the server after registration.").font(.system(size: 10)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                                }
                                Button { Task { if registering { await api.register(username: username, email: email, displayName: displayName, password: password) } else { await api.signIn(identity: username, password: password) } } } label: {
                                    HStack { Spacer(); Text(api.busy ? "Connecting…" : (registering ? "Create account" : "Sign in")); Spacer(); Image(systemName: "arrow.right") }
                                }.buttonStyle(SereinPrimaryButtonStyle()).disabled(api.busy || (registering && (password.unicodeScalars.count < 8 || password.utf8.count > 1024)) || username.isEmpty).animation(.easeInOut(duration: 0.2), value: registering)
                            }
                        }
                    }
                    Text("Account and device settings use the API. Native message encryption and chat history are not connected yet; this screen will not fake a successful chat.").font(.system(size: 10)).foregroundStyle(.secondary)
                }.padding(22).frame(maxWidth: 540).frame(maxWidth: .infinity)
            }
        }
    }
    private func input(_ title: String, text: Binding<String>, icon: String) -> some View {
        HStack { Image(systemName: icon).foregroundStyle(.secondary); TextField(title, text: text).textInputAutocapitalization(.never).autocorrectionDisabled() }.padding(12).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
    }
    private func requirement(_ title: String, met: Bool) -> some View {
        Label(title, systemImage: met ? "checkmark.circle.fill" : "circle").font(.system(size: 10)).foregroundStyle(met ? SereinPalette.green : Color.secondary)
    }
    private func modeButton(_ title: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) { Text(title).font(.system(size: 11, weight: .semibold)).frame(maxWidth: .infinity).padding(10).background(active ? SereinPalette.paleMint : Color.clear, in: RoundedRectangle(cornerRadius: 9)) }
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
                    VStack(spacing: 12) { Image(systemName: "bubble.left.and.bubble.right").font(.system(size: 36)).foregroundStyle(SereinPalette.green); Text("No contacts yet").font(.system(size: 20, weight: .bold)); Text("Add a username from Contacts. Native encrypted message delivery is not connected yet.").font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center).padding(.horizontal, 28); Button("Refresh") { Task { await api.refreshAccountData() } } }
                } else {
                    List(api.contacts) { contact in NavigationLink(destination: SereinNativeConversation(contact: contact)) { HStack(spacing: 11) { SereinAvatar(name: contact.display_name, size: 42); VStack(alignment: .leading, spacing: 3) { Text(contact.display_name).font(.system(size: 13, weight: .semibold)); Text("@\(contact.username) · \(contact.online ? "Online" : "Offline")").font(.system(size: 10)).foregroundStyle(.secondary) }; Spacer(); Text("\(contact.devices.count) devices").font(.system(size: 9)).foregroundStyle(.tertiary) } } }
                        .listStyle(.insetGrouped)
                }
            }.navigationTitle("Chats").toolbar { ToolbarItem(placement: .navigationBarTrailing) { Button { Task { await api.refreshAccountData() } } label: { Image(systemName: "arrow.clockwise") } } }
        }
    }
}

private struct SereinNativeConversation: View {
    let contact: SereinContact
    @State private var text = ""
    var body: some View {
        VStack(spacing: 12) {
            SereinStatusPill(title: "\(contact.devices.count) registered device(s) · \(contact.online ? "online" : "offline")")
            Spacer()
            Image(systemName: "lock.slash").font(.system(size: 34)).foregroundStyle(.orange)
            Text("Messaging is not connected").font(.system(size: 18, weight: .bold))
            Text("Native E2EE, durable local storage, and message delivery are not implemented in this client yet. No message will be sent or falsely marked delivered.").font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Spacer()
            HStack { TextField("Messaging unavailable", text: $text).textFieldStyle(.roundedBorder).disabled(true); Button { } label: { Image(systemName: "arrow.up.circle.fill").font(.system(size: 27)) }.disabled(true) }.padding(.bottom, 8)
        }.padding().navigationTitle(contact.display_name).navigationBarTitleDisplayMode(.inline)
    }
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
                    if incoming.isEmpty { Text("No pending requests.").font(.system(size: 11)).foregroundStyle(.secondary) }
                    ForEach(incoming) { request in HStack { VStack(alignment: .leading) { Text(request.display_name).font(.system(size: 12, weight: .semibold)); Text("@\(request.username)").font(.system(size: 10)).foregroundStyle(.secondary) }; Spacer(); Button("Accept") { Task { await api.acceptContactRequest(request) } }.font(.system(size: 10, weight: .semibold)); Button("Decline", role: .destructive) { Task { await api.dismissContactRequest(request) } }.font(.system(size: 10)) } }
                }
                Section("Contacts") {
                    ForEach(api.contacts) { contact in HStack(spacing: 11) { SereinAvatar(name: contact.display_name); VStack(alignment: .leading) { Text(contact.display_name).font(.system(size: 13, weight: .semibold)); Text("@\(contact.username) · \(contact.devices.count) device(s)").font(.system(size: 10)).foregroundStyle(.secondary) } }.swipeActions { Button("Remove", role: .destructive) { Task { await api.removeContact(contact) } }; Button("Block", role: .destructive) { blockTarget = contact; confirmBlock = true } }
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
    var body: some View {
        NavigationView { VStack(spacing: 15) { Image(systemName: "waveform.path").font(.system(size: 38)).foregroundStyle(SereinPalette.green); Text("Calls are not available").font(.system(size: 20, weight: .bold)); Text("The QUIC echo experiment is not a calling service. Audio/video transport, signaling, key management, and background behavior still need implementation.").font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center); SereinStatusPill(title: "No call was started") }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity).background(Color(uiColor: .systemGroupedBackground)).navigationTitle("Calls") }
    }
}

private struct SereinNativeSettings: View {
    @ObservedObject var api: SereinAPI
    @State private var confirmRevokeOthers = false
    var body: some View {
        NavigationView {
            List {
                Section("Account") { if let user = api.user { SereinDetailRow(title: "Name", value: user.display_name); SereinDetailRow(title: "Username", value: "@\(user.username)"); SereinDetailRow(title: "Email", value: user.email); SereinDetailRow(title: "Verification", value: user.email_verified ? "Verified" : "Not verified") } }
                Section("Appearance") { Picker("Theme", selection: $api.theme) { Text("System").tag("system"); Text("Light").tag("light"); Text("Dark").tag("dark") }; Picker("Text size", selection: $api.fontScale) { Text("Standard").tag("standard"); Text("Large").tag("large") }; Toggle("Reduce motion", isOn: $api.reduceMotion); Toggle("Notifications preference", isOn: $api.notifications); Button("Save preferences") { Task { await api.savePreferences() } } }
                Section("Privacy") { Picker("Online status", selection: $api.presenceVisibility) { Text("Contacts only").tag("contacts"); Text("Nobody").tag("nobody") }; Toggle("Allow contact requests", isOn: $api.allowContactRequests); Toggle("Find me by verified email", isOn: $api.discoverableByEmail); ForEach(api.blocks) { blocked in HStack { Text("@\(blocked.username)"); Spacer(); Button("Unblock") { Task { await api.unblock(blocked) } } } } }
                Section("Registered devices") {
                    ForEach(api.devices) { device in HStack { VStack(alignment: .leading, spacing: 3) { Text(device.name).font(.system(size: 12, weight: .semibold)); Text(device.online == true ? "Online" : (device.last_seen_at ?? "Last active unavailable")).font(.system(size: 10)).foregroundStyle(.secondary) }; Spacer(); if device.current == true { Text("THIS DEVICE").font(.system(size: 8, weight: .bold)).foregroundStyle(SereinPalette.green) } else { Button("Revoke", role: .destructive) { Task { await api.revoke(device) } }.font(.system(size: 10)) } } }
                    Button("Revoke other devices", role: .destructive) { confirmRevokeOthers = true }
                }
                Section("Security status") { Text("The web client encrypts message text with AES-GCM using a shared passphrase, but this is not an audited end-to-end protocol. This native app does not yet encrypt or send messages.").font(.system(size: 11)).foregroundStyle(.secondary); Text("Email verification requires a configured server provider. Account recovery and calls are not configured.").font(.system(size: 11)).foregroundStyle(.secondary) }
                Section { Button("Sign out", role: .destructive) { Task { await api.signOut() } } }
            }.listStyle(.insetGrouped).navigationTitle("Settings")
                .task { await api.refreshAccountData() }
                .confirmationDialog("Revoke other devices? Their local data cannot be remotely erased.", isPresented: $confirmRevokeOthers, titleVisibility: .visible) { Button("Revoke devices", role: .destructive) { Task { await api.revokeOthers() } } }
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

private struct SereinDetailRow: View {
    let title: String
    let value: String
    var body: some View { HStack { Text(title).foregroundStyle(.secondary); Spacer(); Text(value).multilineTextAlignment(.trailing) }.font(.system(size: 12)) }
}
