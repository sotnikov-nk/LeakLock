import SwiftUI

// Liquid Glass on macOS 26+, closest material look on older systems.

extension View {
    func glassCard(cornerRadius: CGFloat = 18) -> some View {
        modifier(GlassCard(cornerRadius: cornerRadius))
    }

    func glassBadge(tint: Color) -> some View {
        modifier(GlassBadge(tint: tint))
    }

    func glassButtons(prominent: Bool = false) -> some View {
        modifier(GlassButtons(prominent: prominent))
    }

    /// Lets the desktop show through the window behind grouped forms.
    func translucentWindow() -> some View {
        modifier(TranslucentWindow())
    }
}

/// Groups glass shapes so they blend and refract together.
struct GlassGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: 12) { content }
        } else {
            content
        }
    }
}

private struct GlassCard: ViewModifier {
    let cornerRadius: CGFloat

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        if #available(macOS 26.0, *) {
            content.glassEffect(.regular, in: shape)
        } else {
            content
                .background(.regularMaterial, in: shape)
                .overlay(shape.strokeBorder(.white.opacity(0.12)))
        }
    }
}

private struct GlassBadge: ViewModifier {
    let tint: Color

    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content.glassEffect(.regular.tint(tint.opacity(0.35)), in: Circle())
        } else {
            content.background(Circle().fill(tint.opacity(0.18)))
        }
    }
}

private struct GlassButtons: ViewModifier {
    let prominent: Bool

    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            if prominent {
                content.buttonStyle(.glassProminent).controlSize(.large)
            } else {
                content.buttonStyle(.glass).controlSize(.large)
            }
        } else {
            if prominent {
                content.buttonStyle(.borderedProminent).controlSize(.large)
            } else {
                content.buttonStyle(.bordered).controlSize(.large)
            }
        }
    }
}

private struct TranslucentWindow: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 15.0, *) {
            content
                .scrollContentBackground(.hidden)
                .containerBackground(.ultraThinMaterial, for: .window)
        } else {
            content
        }
    }
}
