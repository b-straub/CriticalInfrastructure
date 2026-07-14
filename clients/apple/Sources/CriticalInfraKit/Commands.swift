import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Command strings — the wire SSOT, mirroring `shared::terminology` in the Rust
/// workspace. The parameterized commands keep the exact trailing-space / spacing
/// the firmware's `starts_with` + `split_whitespace` parsing expects.
public enum Command {
    public static let whoami = "WHOAMI"
    public static let readSensor = "READ_SENSOR"
    public static let clearAlarm = "CLEAR_ALARM"
    public static let colorGreen = "COLOR green"
    public static let colorYellow = "COLOR yellow"
    public static let colorRed = "COLOR red"
    public static let listRoles = "LIST_ROLES"

    /// e.g. `SET_THRESHOLD 20.0`
    public static func setThreshold(_ celsius: Double) -> String {
        "SET_THRESHOLD \(String(format: "%.1f", celsius))"
    }

    /// e.g. `ADD_ROLE Operator <pk_hex64> <cert_hex128> Bernis-iPad`
    /// The optional device label lets several devices hold the same role and shows
    /// up in `LIST_ROLES` as `name@device`. Metadata, not part of the certificate —
    /// the supervisor-signed command authenticates it.
    public static func addRole(
        name: String, pubkeyHex: String, certSigHex: String, device: String? = nil
    ) -> String {
        var cmd = "ADD_ROLE \(name) \(pubkeyHex) \(certSigHex)"
        if let device, !device.isEmpty { cmd += " \(device)" }
        return cmd
    }

    /// e.g. `REVOKE_ROLE Bernis-iPad` or `REVOKE_ROLE Operator` — the firmware
    /// matches a device label first (revokes that one entry), then falls back to a
    /// role name (revokes all entries holding it).
    public static func revokeRole(name: String) -> String {
        "REVOKE_ROLE \(name)"
    }

    /// Sanitized local device name for role labels: firmware charset
    /// `[A-Za-z0-9._-]`, max 16 chars (spaces/umlauts become `-`).
    public static func deviceLabel() -> String {
        #if os(macOS)
        let raw = Host.current().localizedName ?? "Mac"
        #else
        let raw = UIDevice.current.name
        #endif
        let cleaned = raw.map { c -> Character in
            (c.isASCII && (c.isLetter || c.isNumber)) || c == "." || c == "_" || c == "-" ? c : "-"
        }
        return String(String(cleaned).prefix(16))
    }
}

/// Device roles, mirroring the Rust `Role` enum. The wire string is the raw value.
public enum Role: String, CaseIterable, Sendable {
    case supervisor = "Supervisor"
    case admin = "Admin"
    case `operator` = "Operator"
    case observer = "Observer"

    /// Operational roles — everything the Supervisor is not. The Supervisor is the
    /// role authority (CRUD on roles) and does not operate the device.
    public static var operational: [Role] { [.admin, .`operator`, .observer] }

    /// Operational authority, higher = more (observer < operator < admin). The
    /// Supervisor is 0 (not an operational role).
    public var operationalRank: Int {
        switch self {
        case .observer: return 1
        case .`operator`: return 2
        case .admin: return 3
        case .supervisor: return 0
        }
    }
}

public enum AppConstants {
    /// Default device port (matches `shared::terminology::SUPERVISOR_PORT`).
    public static let defaultPort: UInt16 = 8080
}
