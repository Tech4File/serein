import SwiftUI

@main struct SereinChatApp: App {
    @AppStorage("serein.theme") private var theme = "system"

    init() {
        // Force-link and validate the Rust core before the app proceeds. Live chat still uses the Swift crypto path.
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "SereinVersion") as? String ?? ""
        precondition(SereinCoreBridge.version == appVersion, "Shared Rust core is unavailable or version-mismatched.")
    }
    var body: some Scene {
        WindowGroup {
            SereinProductRootView()
                .preferredColorScheme(theme == "dark" ? .dark : theme == "light" ? .light : nil)
        }
    }
}
