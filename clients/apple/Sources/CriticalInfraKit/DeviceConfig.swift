import Foundation

/// Connection target + the device's public keys. The client's own identity is
/// its Secure Enclave key (see `EnclaveSigner`), so no user/supervisor key lives
/// here — provisioning is baking the enclave pubkey into the firmware or
/// `ADD_ROLE`-ing it.
public struct DeviceConfig: Codable, Equatable, Sendable {
    public var host: String
    public var port: UInt16
    /// Device X25519 "ROM" public key (64 hex) — the envelope DH anchor.
    public var espX25519PubHex: String
    /// Device Ed25519 response-signing public key (64 hex) — verifies replies.
    public var espSigPubHex: String
    /// Absolute path to the CriticalInfrastructure repo checkout — locates `provision/*.sh` for
    /// the macOS Showcase panel. Empty until the user picks it (Settings → Provisioning).
    public var repoPath: String

    public init(
        host: String = "",
        port: UInt16 = AppConstants.defaultPort,
        espX25519PubHex: String = "",
        espSigPubHex: String = "",
        repoPath: String = ""
    ) {
        self.host = host
        self.port = port
        self.espX25519PubHex = espX25519PubHex
        self.espSigPubHex = espSigPubHex
        self.repoPath = repoPath
    }

    // Tolerant decoding so adding a field (e.g. `repoPath`) never wipes an older saved config:
    // every key is optional-on-read and falls back to its default. Encoding stays synthesized.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        port = try c.decodeIfPresent(UInt16.self, forKey: .port) ?? AppConstants.defaultPort
        espX25519PubHex = try c.decodeIfPresent(String.self, forKey: .espX25519PubHex) ?? ""
        espSigPubHex = try c.decodeIfPresent(String.self, forKey: .espSigPubHex) ?? ""
        repoPath = try c.decodeIfPresent(String.self, forKey: .repoPath) ?? ""
    }

    /// The IP and both device keys must be provisioned before use.
    public var needsSetup: Bool {
        host.trimmingCharacters(in: .whitespaces).isEmpty
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
