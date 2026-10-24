import SwiftUI
import UIKit

/// First-party reusable native design primitives; no UI package dependency.
enum SereinPalette {
    static let green = SereinTokens.green
    static let mint = SereinTokens.mint
    static let paleMint = SereinTokens.paleMint
    static let ink = SereinTokens.ink
    static let muted = SereinTokens.muted
    static let warning = SereinTokens.warning
}

struct SereinSectionLabel: View {
    let title: String
    var body: some View {
        Text(title.uppercased()).font(.system(size: 10, weight: .bold, design: .rounded))
            .tracking(1.5).foregroundStyle(.secondary)
    }
}

struct SereinCard<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        content.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(.primary.opacity(0.07), lineWidth: 1))
    }
}

struct SereinPrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 14, weight: .semibold))
            .foregroundStyle(Color.white).frame(maxWidth: .infinity).padding(.vertical, 14)
            .background(SereinPalette.green.opacity(configuration.isPressed ? 0.82 : 1), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.99 : 1)
    }
}

struct SereinSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 13, weight: .semibold)).foregroundStyle(SereinPalette.green)
            .frame(maxWidth: .infinity).padding(.vertical, 12)
            .background(SereinPalette.green.opacity(configuration.isPressed ? 0.12 : 0.07), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct SereinAvatar: View {
    let name: String
    var size: CGFloat = 46
    private var initials: String { name.split(separator: " ").prefix(2).compactMap(\.first).map(String.init).joined().uppercased() }
    private var hue: Double { Double(abs(name.hashValue % 100)) / 100.0 }
    var body: some View {
        Text(initials.isEmpty ? "?" : initials).font(.system(size: size * 0.28, weight: .bold, design: .rounded))
            .foregroundStyle(.white).frame(width: size, height: size)
            .background(LinearGradient(colors: [Color(hue: hue, saturation: 0.39, brightness: 0.58), Color(hue: hue, saturation: 0.52, brightness: 0.39)], startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: size * 0.32, style: .continuous))
            .accessibilityLabel(name)
    }
}

struct SereinStatusPill: View {
    let title: String
    var body: some View {
        HStack(spacing: 6) { Circle().fill(Color.orange).frame(width: 7, height: 7); Text(title) }
            .font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
            .padding(.horizontal, 10).padding(.vertical, 7).background(.secondary.opacity(0.08), in: Capsule())
    }
}
