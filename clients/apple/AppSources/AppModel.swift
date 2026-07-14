import CriticalInfraKit
import Observation
import SwiftUI
#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

/// App state built around **identities**: one Secure Enclave key per role
/// (Supervisor / Admin / Operator / Observer), keyed by the role name. You pick
/// which identity to act as; the Supervisor can register operational roles.
@MainActor
@Observable
final class AppModel {
    var config: DeviceConfig
    /// Roles that have an enclave key on this Mac (pickable identities).
    var availableRoles: [Role]
    /// The identity currently acting as (nil → the picker is shown).
    var activeRole: Role?
    var lastResponse: String?
    var busy = false
    var showConfig: Bool
    /// True while the provisioning & security showcase panel is shown (macOS).
    var showShowcase = false
    /// Compressed pubkey of an inserted PIV / hardware key, if any.
    var hardwareKeyPubHex: String?
    /// Certificate subject of the inserted token's key (e.g. "CriticalInfra
    /// Supervisor"), if any — the on-card name.
    var hardwareCertName: String?
    /// Display name for the inserted token: the user's nickname (Settings) if set,
    /// else the on-card certificate subject.
    var hardwareKeyName: String? {
        if let hw = hardwareKeyPubHex, let nick = config.tokenNicknames[hw], !nick.isEmpty {
            return nick
        }
        return hardwareCertName
    }
    /// True while acting via a hardware key (its device role is enforced remotely).
    var hardwareMode = false

    private var signer: (any CommandSigner)?

    init() {
        let cfg = DeviceConfig.load()
        config = cfg
        showConfig = cfg.needsSetup
        availableRoles = Self.loadAvailableRoles()
        hardwareKeyPubHex = PIVSigner.detect()
        hardwareCertName = PIVSigner.tokenKeyName()
    }

    private static func loadAvailableRoles() -> [Role] {
        let ids = Set(EnclaveSigner.existingIds())
        return Role.allCases.filter { ids.contains($0.rawValue) }
    }

    var hasSupervisor: Bool { availableRoles.contains(.supervisor) }
    var registrableRoles: [Role] { Role.operational.filter { !availableRoles.contains($0) } }
    var revocableRoles: [Role] { Role.operational.filter { availableRoles.contains($0) } }

    func pubkeyHex(for role: Role) -> String? { EnclaveSigner.publicKeyHex(id: role.rawValue) }

    /// Public key (66-hex compressed P-256) of the identity currently acting as —
    /// enclave or hardware. This is what gets baked into the firmware.
    var activePublicKeyHex: String? { signer?.publicKeyHex }

    /// True when the active identity is backed by an inserted hardware key.
    var activeIsHardware: Bool { signer is PIVSigner }

    // MARK: - Identity lifecycle

    /// (a) No keys yet → create the Supervisor key. Its public key is then baked
    /// into the firmware as SUPERVISOR_PUBKEY.
    func registerSupervisor() {
        do {
            _ = try EnclaveSigner(id: Role.supervisor.rawValue, createIfMissing: true)
            availableRoles = Self.loadAvailableRoles()
            lastResponse = nil
        } catch {
            lastResponse = "Secure Enclave: \(error)"
        }
    }

    /// (c) Pick an identity to act as.
    func select(_ role: Role) {
        do {
            signer = try EnclaveSigner(id: role.rawValue, createIfMissing: false)
            activeRole = role
            lastResponse = nil
        } catch {
            lastResponse = "\(error)"
        }
    }

    func switchIdentity() {
        signer = nil
        activeRole = nil
        hardwareMode = false
        lastResponse = nil
        availableRoles = Self.loadAvailableRoles()
        hardwareKeyPubHex = PIVSigner.detect()
        hardwareCertName = PIVSigner.tokenKeyName()
    }

    /// Re-scan for an inserted hardware key.
    func refreshHardware() {
        hardwareKeyPubHex = PIVSigner.detect()
        hardwareCertName = PIVSigner.tokenKeyName()
    }

    /// This device's key label for enclave-key role enrollment: the Settings
    /// override if set, else the sanitized OS device name.
    var resolvedDeviceLabel: String {
        let override = config.deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        return override.isEmpty ? Command.localDeviceLabel() : Command.sanitizeLabel(override)
    }

    /// Set (or clear, with "") the nickname for a hardware key by its pubkey.
    func setTokenNickname(_ nickname: String, forPubkey pubkey: String) {
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            config.tokenNicknames.removeValue(forKey: pubkey)
        } else {
            config.tokenNicknames[pubkey] = trimmed
        }
        config.save()
    }

    /// Act via the inserted hardware key. Its device role is enforced by the
    /// device (discover it with WHOAMI); nothing about the role is known locally.
    func useHardwareKey() {
        do {
            signer = try PIVSigner()
            hardwareMode = true
            activeRole = nil
            lastResponse = nil
        } catch {
            lastResponse = "\(error)"
        }
    }

    /// Act as the **Supervisor** using the inserted hardware key. For the device
    /// to accept this, the card's public key must be baked into the firmware as
    /// SUPERVISOR_PUBKEY (copy it from the panel); otherwise the device rejects
    /// the — validly signed — command as an unknown supervisor.
    func useHardwareKeyAsSupervisor() {
        do {
            signer = try PIVSigner()
            activeRole = .supervisor
            hardwareMode = false
            lastResponse = nil
        } catch {
            lastResponse = "\(error)"
        }
    }

    // MARK: - Supervisor actions (role CRUD)

    /// (b) Supervisor registers an operational role: create its enclave key and
    /// ADD_ROLE it on the device (two Supervisor Touch IDs: certificate + command).
    func registerRole(_ role: Role) {
        guard let supervisor = signer, activeRole == .supervisor else {
            lastResponse = "Select the Supervisor identity first."
            return
        }
        let cfg = config
        Task {
            busy = true
            defer { busy = false }
            do {
                let roleKey = try EnclaveSigner(id: role.rawValue, createIfMissing: true)
                let cmd = try Provisioning.addRoleCommand(
                    role: role.rawValue,
                    newPublicKeyHex: roleKey.publicKeyHex,
                    supervisor: supervisor,
                    label: resolvedDeviceLabel // enclave key lives here -> this device's name
                )
                let client = DeviceClient(config: cfg, signer: supervisor)
                lastResponse = await client.send(cmd)
                availableRoles = Self.loadAvailableRoles()
            } catch {
                // Don't leave a half-created local key if provisioning failed.
                EnclaveSigner.reset(id: role.rawValue)
                availableRoles = Self.loadAvailableRoles()
                lastResponse = "Register failed: \(error)"
            }
        }
    }

    func revokeRole(_ role: Role) {
        guard let supervisor = signer, activeRole == .supervisor else { return }
        let cfg = config
        Task {
            busy = true
            defer { busy = false }
            let client = DeviceClient(config: cfg, signer: supervisor)
            let resp = await client.send(Command.revokeRole(name: role.rawValue))
            EnclaveSigner.reset(id: role.rawValue) // drop the local key too
            availableRoles = Self.loadAvailableRoles()
            lastResponse = resp
        }
    }

    func listRoles() {
        guard let supervisor = signer, activeRole == .supervisor else { return }
        sendAs(supervisor, Command.listRoles)
    }

    /// Supervisor provisions an EXTERNAL public key (a hardware key, or another
    /// device's enclave key) as a role — no local key is created here, so the
    /// private key stays where it lives (the card / the other device). The key
    /// label (required) names where the key lives — device or token name — for
    /// LIST_ROLES / targeted revocation.
    func provisionExternal(pubkeyHex: String, as role: Role, label: String) {
        guard let supervisor = signer, activeRole == .supervisor else {
            lastResponse = "Select the Supervisor identity first."
            return
        }
        let pk = pubkeyHex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard pk.count == 66 else {
            lastResponse = "Public key must be 66 hex characters (compressed P-256)."
            return
        }
        let sanitized = Command.sanitizeLabel(label.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !sanitized.isEmpty else {
            lastResponse = "A key label is required (device or token name) — the firmware rejects unlabeled grants."
            return
        }
        let cfg = config
        Task {
            busy = true
            defer { busy = false }
            do {
                let cmd = try Provisioning.addRoleCommand(
                    role: role.rawValue, newPublicKeyHex: pk, supervisor: supervisor,
                    label: sanitized)
                let client = DeviceClient(config: cfg, signer: supervisor)
                lastResponse = await client.send(cmd)
            } catch {
                lastResponse = "Provision failed: \(error)"
            }
        }
    }

    // MARK: - Operational actions

    func send(_ command: String) {
        guard let signer, activeRole != .supervisor else {
            lastResponse = "The Supervisor cannot run operational commands."
            return
        }
        sendAs(signer, command)
    }

    private func sendAs(_ signer: CommandSigner, _ command: String) {
        let cfg = config
        Task {
            busy = true
            defer { busy = false }
            let client = DeviceClient(config: cfg, signer: signer)
            lastResponse = await client.send(command)
        }
    }

    func saveConfig() {
        config.save()
        showConfig = config.needsSetup
    }

    /// Import a device descriptor JSON (from `provision/show-device-keys.sh`) into
    /// the current config — keys, and host/name if present. Returns a status
    /// message. Public-key data only; nothing secret is imported.
    @discardableResult
    func importConfig(json: Data) -> Bool {
        do {
            try config.apply(importJSON: json)
            config.save()
            showConfig = config.needsSetup
            lastResponse = "Imported device keys\(config.host.isEmpty ? "" : " + host \(config.host)")."
            return true
        } catch {
            lastResponse = "Import failed: \(error)"
            return false
        }
    }

    /// Import from the system clipboard (the script copies the JSON there;
    /// Universal Clipboard carries it from a nearby Mac to iPhone/iPad).
    @discardableResult
    func importConfigFromClipboard() -> Bool {
        #if canImport(AppKit)
        let text = NSPasteboard.general.string(forType: .string)
        #elseif canImport(UIKit)
        let text = UIPasteboard.general.string
        #else
        let text: String? = nil
        #endif
        guard let text, let data = text.data(using: .utf8) else {
            lastResponse = "Clipboard is empty — run provision/show-device-keys.sh first."
            return false
        }
        return importConfig(json: data)
    }
}
