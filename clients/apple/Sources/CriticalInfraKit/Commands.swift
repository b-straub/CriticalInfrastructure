import Foundation

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

    /// e.g. `ADD_ROLE Operator <pk_hex64> <cert_hex128>`
    public static func addRole(name: String, pubkeyHex: String, certSigHex: String) -> String {
        "ADD_ROLE \(name) \(pubkeyHex) \(certSigHex)"
    }

    /// e.g. `REVOKE_ROLE Operator` (the target is parsed from the decrypted
    /// command by the firmware — see the REVOKE_ROLE fix in commands.rs).
    public static func revokeRole(name: String) -> String {
        "REVOKE_ROLE \(name)"
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
    /// The PRF salt string. The actual WebAuthn PRF input is its SHA-256 (see
    /// PasskeyAuthenticator.prfSalt) — identical to the web client's
    /// `SHA-256("CriticalInfra_Supervisor_Salt_V1")`.
    public static let prfSaltString = "CriticalInfra_Supervisor_Salt_V1"

    /// Default device port (matches `shared::terminology::SUPERVISOR_PORT`).
    public static let defaultPort: UInt16 = 8080
}
