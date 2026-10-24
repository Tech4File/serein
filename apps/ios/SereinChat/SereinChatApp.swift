import SwiftUI

@main struct SereinChatApp: App {
    @AppStorage("serein.theme") private var theme = "system"
    var body: some Scene {
        WindowGroup {
            SereinProductRootView()
                .preferredColorScheme(theme == "dark" ? .dark : theme == "light" ? .light : nil)
        }
    }
}
