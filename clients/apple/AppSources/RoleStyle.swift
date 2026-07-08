import CriticalInfraKit
import SwiftUI

/// UI styling for roles (app-side — the Kit stays UI-free).
extension Role {
    var symbol: String {
        switch self {
        case .supervisor: return "key.horizontal.fill"
        case .admin: return "shield.lefthalf.filled"
        case .`operator`: return "slider.horizontal.3"
        case .observer: return "eye.fill"
        }
    }

    var tint: Color {
        switch self {
        case .supervisor: return .purple
        case .admin: return .blue
        case .`operator`: return .teal
        case .observer: return .gray
        }
    }

    var blurb: String {
        switch self {
        case .supervisor: return "Role authority — create, list, revoke roles"
        case .admin: return "Full operations: sensor, threshold, alarm"
        case .`operator`: return "Operate: sensor, threshold"
        case .observer: return "Read-only: sensor"
        }
    }
}

/// A rounded, app-icon-style tinted badge for a role.
struct RoleBadge: View {
    let role: Role
    var size: CGFloat = 40

    var body: some View {
        Image(systemName: role.symbol)
            .font(.system(size: size * 0.44, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(role.tint.gradient, in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous))
            .shadow(color: role.tint.opacity(0.35), radius: 4, y: 2)
    }
}

/// Header shown at the top of a role's panel.
struct RoleHero: View {
    let role: Role

    var body: some View {
        HStack(spacing: 14) {
            RoleBadge(role: role, size: 54)
            VStack(alignment: .leading, spacing: 3) {
                Text(role.rawValue).font(.title2.bold())
                Text(role.blurb).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
