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
    /// Inline status for the Settings "Import config" action (kept out of lastResponse so it
    /// shows next to the button and doesn't close Settings).
    var importStatus: String?
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

    /// Delete a local Secure Enclave identity (a stale/unwanted key on THIS device). Only
    /// removes the local key — it does NOT touch the device's roles (a supervisor must REVOKE
    /// a role on the device separately). If it's the active identity, switch away.
    func forgetIdentity(_ role: Role) {
        EnclaveSigner.reset(id: role.rawValue)
        if activeRole == role { switchIdentity() }
        availableRoles = Self.loadAvailableRoles()
        lastResponse = "Forgot the local “\(role.rawValue)” key on this device."
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
                let resp = await client.send(cmd)
                lastResponse = resp
                availableRoles = Self.loadAvailableRoles()
                // Optimistically reflect the grant in the device-roles view (only if we've fetched
                // it — nil means "unknown", leave it so other rows keep their local-key fallback).
                // Whole-value reassignment (not `deviceRoles?.append`) so @Observable reliably sees
                // the mutation and re-renders the row immediately, without a Refresh round-trip.
                if resp.contains("Added Securely"), var roles = deviceRoles {
                    let mine = resolvedDeviceLabel
                    roles.removeAll { $0.name == role.rawValue && $0.label == mine }
                    roles.append(Command.DeviceRole(
                        name: role.rawValue, label: mine, pubkeyHex: roleKey.publicKeyHex))
                    deviceRoles = roles
                }
            } catch {
                // Don't leave a half-created local key if provisioning failed.
                EnclaveSigner.reset(id: role.rawValue)
                availableRoles = Self.loadAvailableRoles()
                lastResponse = "Register failed: \(error)"
            }
        }
    }

    /// Revoke ONLY this device's key for `role` — targeted as `role@thisDeviceLabel`, so it
    /// never removes another device's same-named role. Also drops the local enclave key.
    func revokeRole(_ role: Role) {
        guard let supervisor = signer, activeRole == .supervisor else { return }
        let label = resolvedDeviceLabel
        let cfg = config
        Task {
            busy = true
            defer { busy = false }
            let client = DeviceClient(config: cfg, signer: supervisor)
            let resp = await client.send(Command.revokeRole(roleAtLabel: "\(role.rawValue)@\(label)"))
            EnclaveSigner.reset(id: role.rawValue) // drop this device's local key too
            availableRoles = Self.loadAvailableRoles()
            lastResponse = resp
            // Whole-value reassignment so @Observable re-renders the row at once (see registerRole).
            if resp.contains("Revoked"), var roles = deviceRoles {
                roles.removeAll { $0.name == role.rawValue && $0.label == label }
                deviceRoles = roles
            }
        }
    }

    /// Roles the DEVICE actually reports (from the last LIST_ROLES) — nil until refreshed.
    /// The role rows show THIS (device truth), not just which enclave keys exist locally.
    var deviceRoles: [Command.DeviceRole]? = nil

    /// Whether the device has THIS device's key for `role` — scoped to this device's label, so
    /// each device sees only its own roles (never another device's same-named role). Matched on
    /// the exact label the precise revoke (`role@label`) targets, so the row and Revoke stay in
    /// lockstep. nil = not yet refreshed.
    func deviceHasRole(_ role: Role) -> Bool? {
        guard let dr = deviceRoles else { return nil }
        let mine = resolvedDeviceLabel
        return dr.contains { $0.name == role.rawValue && $0.label == mine }
    }

    /// Whether THIS device's local enclave key for `role` is one the device actually trusts —
    /// matched by PUBKEY against the last LIST_ROLES. This is the real "can I act as this here?"
    /// test: a same-named local key with a different pubkey (e.g. registered on another device)
    /// is rejected. nil = not scanned yet or no local key. Operational roles only (the supervisor
    /// is validated against the baked SUPERVISOR_PUBKEY, not the role table).
    func deviceAccepts(_ role: Role) -> Bool? {
        guard role != .supervisor, let dr = deviceRoles,
              let localPk = EnclaveSigner.publicKeyHex(id: role.rawValue)?.lowercased()
        else { return nil }
        return dr.contains { $0.name == role.rawValue && $0.pubkeyHex.lowercased() == localPk }
    }

    func listRoles() {
        guard let supervisor = signer, activeRole == .supervisor else { return }
        let cfg = config
        Task {
            busy = true
            defer { busy = false }
            let client = DeviceClient(config: cfg, signer: supervisor)
            let resp = await client.send(Command.listRoles)
            lastResponse = resp
            if let roles = Command.parseRolesResponse(resp) { deviceRoles = roles }
        }
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
            // Keep Settings OPEN after import — the user reviews the filled fields and closes
            // manually. importStatus drives an inline confirmation next to the button.
            importStatus = "Imported device keys\(config.host.isEmpty ? "" : " + host \(config.host)")."
            return true
        } catch {
            importStatus = "Import failed: \(error)"
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
            importStatus = "Clipboard is empty — run provision/show-device-keys.sh first."
            return false
        }
        return importConfig(json: data)
    }
}
