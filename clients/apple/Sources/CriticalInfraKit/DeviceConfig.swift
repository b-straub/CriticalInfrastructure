import Foundation

/// Which link the client talks to the device over.
public enum TransportKind: String, Codable, Sendable, CaseIterable {
    case udp   // Wi-Fi datagrams (same LAN)
    case ble   // Bluetooth LE GATT (no network)
}

/// Connection target + the device's public keys. The client's own identity is
/// its Secure Enclave key (see `EnclaveSigner`), so no user/supervisor key lives
/// here — provisioning is baking the enclave pubkey into the firmware or
/// `ADD_ROLE`-ing it.
public struct DeviceConfig: Codable, Equatable, Sendable {
    /// Transport link. UDP needs `host`/`port`; BLE needs `bleName` (device keys are shared).
    public var transport: TransportKind
    public var host: String
    public var port: UInt16
    /// Device X25519 "ROM" public key (64 hex) — the envelope DH anchor.
    public var espX25519PubHex: String
    /// Device Ed25519 response-signing public key (64 hex) — verifies replies.
    public var espSigPubHex: String
    /// BLE peripheral advertised name to scan for (default matches the firmware).
    public var bleName: String
    /// Absolute path to the CriticalInfrastructure repo checkout — locates `provision/*.sh` for
    /// the macOS Showcase panel. Empty until the user picks it (Settings → Provisioning).
    public var repoPath: String

    /// Vendor GATT service + characteristic UUIDs, matching `target-esp32s3/src/ble.rs`.
    public static let bleServiceUUID = "9E7312E0-2354-11EB-9F10-FBC30A62CF38"
    public static let bleRxCharUUID = "9E7312E0-2354-11EB-9F10-FBC30A62CF39"  // client → device (write)
    public static let bleTxCharUUID = "9E7312E0-2354-11EB-9F10-FBC30A62CF3A"  // device → client (notify)

    public init(
        transport: TransportKind = .udp,
        host: String = "",
        port: UInt16 = AppConstants.defaultPort,
        espX25519PubHex: String = "",
        espSigPubHex: String = "",
        bleName: String = "CriticalInfra",
        repoPath: String = ""
    ) {
        self.transport = transport
        self.host = host
        self.port = port
        self.espX25519PubHex = espX25519PubHex
        self.espSigPubHex = espSigPubHex
        self.bleName = bleName
        self.repoPath = repoPath
    }

    // Tolerant decoding so adding a field (e.g. `repoPath`, `transport`) never wipes an older
    // saved config: every key is optional-on-read and falls back to its default.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        transport = try c.decodeIfPresent(TransportKind.self, forKey: .transport) ?? .udp
        host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        port = try c.decodeIfPresent(UInt16.self, forKey: .port) ?? AppConstants.defaultPort
        espX25519PubHex = try c.decodeIfPresent(String.self, forKey: .espX25519PubHex) ?? ""
        espSigPubHex = try c.decodeIfPresent(String.self, forKey: .espSigPubHex) ?? ""
        bleName = try c.decodeIfPresent(String.self, forKey: .bleName) ?? "CriticalInfra"
        repoPath = try c.decodeIfPresent(String.self, forKey: .repoPath) ?? ""
    }

    /// The device keys are always required. UDP additionally needs a host; BLE needs a name.
    public var needsSetup: Bool {
        let addressed = switch transport {
        case .udp: !host.trimmingCharacters(in: .whitespaces).isEmpty
        case .ble: !bleName.trimmingCharacters(in: .whitespaces).isEmpty
        }
        return !addressed
            || espX25519PubHex.count != 64
            || espSigPubHex.count != 64
    }

    private static let key = "criticalinfra.deviceconfig"

    public static func load() -> DeviceConfig {
        guard let data = UserDefaults.standard.data(forKey: key),
              let cfg = try? JSONDecoder().decode(DeviceConfig.self, from: data)
        else { return DeviceConfig() }
        return cfg
    }

    public func save() {
        if let data = try? JSONEncoder().encode(self) {
            UserDefaults.standard.set(data, forKey: Self.key)
        }
    }
}
