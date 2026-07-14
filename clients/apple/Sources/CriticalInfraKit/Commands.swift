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

    /// e.g. `ADD_ROLE Operator <pk_hex64> <cert_hex128> iPad-01`
    /// The key label is REQUIRED (the firmware rejects an unlabeled grant): it names
    /// where the key lives — a device name for enclave keys, the token/cert name for
    /// PIV hardware keys — and shows up in `LIST_ROLES` as `name@label`. Metadata,
    /// not part of the certificate — the supervisor-signed command authenticates it.
    public static func addRole(
        name: String, pubkeyHex: String, certSigHex: String, label: String
    ) -> String {
        "ADD_ROLE \(name) \(pubkeyHex) \(certSigHex) \(label)"
    }

    /// e.g. `REVOKE_ROLE iPad-01` or `REVOKE_ROLE Operator` — the firmware
    /// matches a key label first (revokes that one entry), then falls back to a
    /// role name (revokes all entries holding it).
    public static func revokeRole(name: String) -> String {
        "REVOKE_ROLE \(name)"
    }

    /// Sanitize a proposed key label to the firmware charset `[A-Za-z0-9._-]`,
    /// max 16 chars (spaces/umlauts become `-`).
    public static func sanitizeLabel(_ raw: String) -> String {
        let cleaned = raw.map { c -> Character in
            (c.isASCII && (c.isLetter || c.isNumber)) || c == "." || c == "_" || c == "-" ? c : "-"
        }
        return String(String(cleaned).prefix(16))
    }

    /// A role as the DEVICE reports it in LIST_ROLES: role name + key label + the trusted pubkey.
    public struct DeviceRole: Equatable, Sendable {
        public let name: String
        public let label: String       // "" for legacy unlabeled entries
        public let pubkeyHex: String   // 66-hex compressed P-256 key the device trusts for this role
        public init(name: String, label: String, pubkeyHex: String = "") {
            self.name = name; self.label = label; self.pubkeyHex = pubkeyHex
        }
    }

    /// Parse a LIST_ROLES device response into the roles actually stored on the device.
    /// `"No roles found"` → `[]`; `"ROLES:Admin@Mac:03..,Observer@Mac:02.."` → the entries.
    /// Returns nil when the string isn't a roles response (so callers don't clobber state on
    /// an error/unrelated reply). One role can appear multiple times with different labels.
    public static func parseRolesResponse(_ response: String) -> [DeviceRole]? {
        let t = response.trimmingCharacters(in: .whitespacesAndNewlines)
        if t == "No roles found" { return [] }
        guard t.hasPrefix("ROLES:") else { return nil }
        let body = t.dropFirst("ROLES:".count)
        var out: [DeviceRole] = []
        for entry in body.split(separator: ",") where !entry.isEmpty {
            // entry = "name@label:pk" or (legacy) "name:pk" — the pk follows the first ':'.
            let parts = entry.split(separator: ":", maxSplits: 1)
            let head = parts.first.map(String.init) ?? String(entry)
            let pk = parts.count > 1 ? String(parts[1]) : ""
            if let at = head.firstIndex(of: "@") {
                out.append(DeviceRole(name: String(head[..<at]),
                                      label: String(head[head.index(after: at)...]), pubkeyHex: pk))
            } else {
                out.append(DeviceRole(name: head, label: "", pubkeyHex: pk))
            }
        }
        return out
    }

    /// Sanitized local device name — the key label for keys living in THIS
    /// device's Secure Enclave.
    public static func localDeviceLabel() -> String {
        #if os(macOS)
        let raw = Host.current().localizedName ?? "Mac"
        #else
        let raw = UIDevice.current.name
        #endif
        return sanitizeLabel(raw)
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
