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
        Text(title.uppercased()).font(.system(size: 10, weight: .bold, design: .rounded, relativeTo: .body))
            .tracking(1.5).foregroundStyle(.secondary)
    }
}

struct SereinCard<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        content.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: SereinTokens.dialogRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: SereinTokens.dialogRadius, style: .continuous).stroke(.primary.opacity(0.07), lineWidth: 1))
    }
}

struct SereinChip: View {
    let title: String
    let selected: Bool
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(.subheadline, design: .rounded).weight(.semibold))
                .frame(minHeight: SereinTokens.chipHeight)
                .padding(.horizontal, 13)
                .foregroundStyle(selected ? SereinPalette.green : Color.primary.opacity(0.76))
                .background(selected ? SereinPalette.green.opacity(0.13) : Color(uiColor: .secondarySystemBackground), in: Capsule())
                .overlay(Capsule().stroke(selected ? SereinPalette.green.opacity(0.42) : Color.primary.opacity(0.08), lineWidth: 1))
        }.buttonStyle(.plain).accessibilityAddTraits(selected ? .isSelected : [])
    }
}

struct SereinPrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 14, weight: .semibold, relativeTo: .body))
            .foregroundStyle(Color.white).frame(maxWidth: .infinity, minHeight: SereinTokens.buttonHeight)
            .background(SereinPalette.green.opacity(configuration.isPressed ? 0.82 : 1), in: RoundedRectangle(cornerRadius: SereinTokens.buttonRadius, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.99 : 1)
    }
}

struct SereinSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 13, weight: .semibold, relativeTo: .body)).foregroundStyle(SereinPalette.green)
            .frame(maxWidth: .infinity, minHeight: SereinTokens.buttonHeight)
            .background(SereinPalette.green.opacity(configuration.isPressed ? 0.12 : 0.07), in: RoundedRectangle(cornerRadius: SereinTokens.buttonRadius, style: .continuous))
    }
}

struct SereinIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 17, weight: .semibold, design: .rounded)).foregroundStyle(SereinPalette.green)
            .frame(width: SereinTokens.iconButtonSize, height: SereinTokens.iconButtonSize)
            .background(SereinPalette.green.opacity(configuration.isPressed ? 0.20 : 0.11), in: RoundedRectangle(cornerRadius: SereinTokens.buttonRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: SereinTokens.buttonRadius, style: .continuous).stroke(SereinPalette.green.opacity(0.20), lineWidth: 1))
    }
}

struct SereinDestructiveButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 13, weight: .semibold, relativeTo: .body)).foregroundStyle(Color.white)
            .frame(maxWidth: .infinity, minHeight: SereinTokens.buttonHeight)
            .background(Color(red: 0.68, green: 0.14, blue: 0.16).opacity(configuration.isPressed ? 0.78 : 1), in: RoundedRectangle(cornerRadius: SereinTokens.buttonRadius, style: .continuous))
    }
}

struct SereinAvatar: View {
    let name: String
    var size: CGFloat = 46
    private var initials: String { name.split(separator: " ").prefix(2).compactMap(\.first).map(String.init).joined().uppercased() }
    private var hue: Double { Double(abs(name.hashValue % 100)) / 100.0 }
    var body: some View {
        Text(initials.isEmpty ? "?" : initials).font(.system(size: max(10, size * 0.28), weight: .bold, design: .rounded, relativeTo: .body))
            .foregroundStyle(.white).frame(width: size, height: size)
            .background(LinearGradient(colors: [Color(hue: hue, saturation: 0.39, brightness: 0.58), Color(hue: hue, saturation: 0.52, brightness: 0.39)], startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: size * 0.32, style: .continuous))
            .accessibilityLabel(name)
    }
}

struct SereinStatusPill: View {
    let title: String
    var body: some View {
        HStack(spacing: 6) { Circle().fill(Color.orange).frame(width: 7, height: 7); Text(title) }
            .font(.system(size: 10, weight: .medium, relativeTo: .body)).foregroundStyle(.secondary)
            .padding(.horizontal, 10).padding(.vertical, 7).background(.secondary.opacity(0.08), in: Capsule())
    }
}
