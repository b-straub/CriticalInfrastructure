import Foundation

/// Declarative catalog for the in-app provisioning & security **showcase** — three ordered
/// phases (1 provisioning → full seal, 2 testing, 3 OTA firmware updates) mapped to guided
/// steps over the `provision/*.sh` pipeline.
///
/// This file is deliberately UI-free and side-effect-free so `swift test` covers it: it only
/// *describes* steps and *resolves* them to a concrete command line. Actually running a step
/// (inline `Process`, or launching Terminal) lives in the macOS app target — see
/// `ScriptRunner` / `TerminalLauncher`.
///
/// Credentials (Wi-Fi SSID/pass, supervisor pubkey) are never passed as arguments — the scripts
/// read them from the macOS Keychain via `provision/lib.sh`'s `load_creds`. Only the device IP,
/// a USB port, and literal flags are resolved here.

/// How a step is executed.
public enum RunMode: Sendable, Equatable {
    /// Safe to run headless: the app spawns it via `Process`, streams output, reads the exit code.
    case inline
    /// Has an interactive gate (token PIN, `espefuse` BURN confirm, backup-token `read -p`) that
    /// cannot be driven over a pipe — the app launches it in a real terminal instead.
    case terminal
    /// No script at all (e.g. keyroost's on-card key generation is a GUI tool) — instructions only.
    case manual
}

/// The outcome of an inline run, derived from the script's exit code.
public enum Verdict: Sendable, Equatable {
    case pass
    case fail
    case warn(String)
    case unknown
}

/// A single argument of a step, resolved at run time against the connection config + a port pick.
public enum ArgSpec: Sendable, Equatable {
    /// A fixed flag or token, e.g. `--yes-burn`, `--keys`, `mainToken`.
    case literal(String)
    /// `--host <device-ip>` — from `DeviceConfig.host` (scripts fall back to the Keychain if empty).
    case host
    /// `--port <dev>` — the selected `/dev/cu.*`. Omitted entirely when no port is chosen, so the
    /// script's own auto-detect kicks in.
    case port
}

/// One guided step. `verdict` maps a script exit code to a user-facing outcome.
public struct ShowcaseStep: Identifiable, Sendable {
    public let id: String
    public let title: String
    /// The "why", shown as a caption under the title.
    public let rationale: String
    /// Script basename under `provision/` (e.g. `verify-seal.sh`); `nil` for `.manual` steps.
    public let script: String?
    public let args: [ArgSpec]
    public let mode: RunMode
    /// Extra note surfaced for `.terminal` steps (e.g. "enter the token PIN when prompted").
    public let terminalHint: String?
    /// Maps a process exit status to a `Verdict` (only meaningful for `.inline` steps).
    public let verdict: @Sendable (Int32) -> Verdict

    public init(
        id: String,
        title: String,
        rationale: String,
        script: String?,
        args: [ArgSpec] = [],
        mode: RunMode,
        terminalHint: String? = nil,
        verdict: @escaping @Sendable (Int32) -> Verdict = ShowcaseStep.exitZeroPass
    ) {
        self.id = id
        self.title = title
        self.rationale = rationale
        self.script = script
        self.args = args
        self.mode = mode
        self.terminalHint = terminalHint
        self.verdict = verdict
    }

    /// Generic verdict: exit 0 → pass, anything else → fail.
    public static let exitZeroPass: @Sendable (Int32) -> Verdict = { $0 == 0 ? .pass : .fail }

    /// `ota-attack-test.sh`: 0 = all refused at intended check, 1 = a push was accepted
    /// (un-hardened firmware), 2 = all refused but some short-circuited by the version gate.
    public static let attackTestVerdict: @Sendable (Int32) -> Verdict = { code in
        switch code {
        case 0: return .pass
        case 2: return .warn("all refused, but re-run with --build-base to exercise the RSA path")
        default: return .fail
        }
    }
}

/// One of the three showcase phases.
public struct ShowcaseArea: Identifiable, Sendable {
    public let id: String
    public let title: String
    /// SF Symbol name for the area header.
    public let icon: String
    public let blurb: String
    public let steps: [ShowcaseStep]

    public init(id: String, title: String, icon: String, blurb: String, steps: [ShowcaseStep]) {
        self.id = id
        self.title = title
        self.icon = icon
        self.blurb = blurb
        self.steps = steps
    }
}

/// A resolved, ready-to-run invocation of a step.
public struct ScriptInvocation: Sendable, Equatable {
    /// Absolute path to the script, e.g. `<repo>/provision/verify-seal.sh`.
    public let scriptPath: String
    public let args: [String]
    /// Human-facing command line for the "Copy command" button, repo-relative for readability.
    public let display: String
}

/// Resolve a step against the repo location, connection config and an optional selected USB port.
/// Returns `nil` for `.manual` steps (no script) or when a required input is missing.
public func resolveShowcaseStep(
    _ step: ShowcaseStep,
    repoPath: String,
    config: DeviceConfig,
    port: String?
) -> ScriptInvocation? {
    guard let script = step.script else { return nil }

    var args: [String] = []
    for spec in step.args {
        switch spec {
        case .literal(let s):
            args.append(s)
        case .host:
            let host = config.host.trimmingCharacters(in: .whitespaces)
            if !host.isEmpty {
                args.append(contentsOf: ["--host", host])
            }
        case .port:
            if let port, !port.isEmpty {
                args.append(contentsOf: ["--port", port])
            }
        }
    }

    let base = repoPath.hasSuffix("/") ? String(repoPath.dropLast()) : repoPath
    let scriptPath = "\(base)/provision/\(script)"
    let display = (["provision/\(script)"] + args).joined(separator: " ")
    return ScriptInvocation(scriptPath: scriptPath, args: args, display: display)
}

/// Three clearly-separated phases, in order:
///   1. **Provisioning** — the one-way arc to a fully sealed board (do it ONCE, in order, on a
///      fresh unit; each irreversible burn has a rehearse immediately before it).
///   2. **Testing** — read-only network + cable checks that prove the lockdown. Safe anytime.
///   3. **Updates** — OTA, the only way to change firmware after phase 1 is done.
/// Inline steps are safe to run headless; terminal steps have an interactive gate; manual steps
/// have no script.
public enum ShowcaseCatalog {
    public static let areas: [ShowcaseArea] = [provisioning, testing, updates]

    // MARK: Phase 1 — Provisioning (one-way to full seal)
    static let provisioning = ShowcaseArea(
        id: "provision",
        title: "1 · Provisioning",
        icon: "lock.shield",
        blurb: "The irreversible arc to a fully sealed board. Do it ONCE, top to bottom, on a FRESH unit — each burn has a rehearse just above it. When it ends, the cable is locked out and OTA (phase 3) is the only way in.",
        steps: [
            // --- signing keys (no burns) ---
            ShowcaseStep(
                id: "keys.keygen",
                title: "Generate on-card PIV keys",
                rationale: "keyroost generates the RSA-3072 secure-boot key (slot 9a) and the P-256 supervisor key (slot 9c) directly on the main token — the private key never exists off-card.",
                script: nil,
                mode: .manual,
                terminalHint: "Open keyroost (github.com/framefilter/keyroost) and generate the keys on the inserted token."
            ),
            ShowcaseStep(
                id: "keys.enroll",
                title: "Enroll the main token",
                rationale: "Reads the on-card public key, writes the PKCS#11 signing config, and computes the Secure Boot v2 digest that gets burned later. Nothing is burned here.",
                script: "1-enroll-key.sh",
                args: [.literal("--name"), .literal("mainToken")],
                mode: .inline
            ),
            ShowcaseStep(
                id: "keys.enroll.backupToken",
                title: "Enroll the backup token",
                rationale: "The same for the backup RSA-3072 signer (DIGEST1). Signing every image with both keys means losing one token never locks you out of OTA recovery. The backup card needs OpenSC's PIV-II driver.",
                script: "1-enroll-key.sh",
                args: [.literal("--name"), .literal("backupToken"), .literal("--driver"), .literal("PIV-II")],
                mode: .inline
            ),
            // --- eFuse identity + JTAG (NOT secure download — that's the final seal) ---
            ShowcaseStep(
                id: "device.harden.rehearse",
                title: "eFuse harden — rehearse",
                rationale: "Dry-run the HMAC identity + JTAG-off burns on a virtual ESP32-S3. No board required, nothing burned. (Secure Download Mode is NOT burned here — it must come after Secure Boot, so it's deferred to the final seal.)",
                script: "2-efuse-harden.sh",
                args: [.port],
                mode: .inline
            ),
            ShowcaseStep(
                id: "device.harden.burn",
                title: "eFuse harden — REAL burn",
                rationale: "Burns the read-protected HMAC identity root and disables JTAG (DIS_PAD_JTAG, DIS_USB_JTAG). Does NOT enable Secure Download Mode (that would block the Secure Boot burn below). Irreversible.",
                script: "2-efuse-harden.sh",
                args: [.port, .literal("--yes-burn")],
                mode: .terminal,
                terminalHint: "espefuse will ask you to type BURN to confirm."
            ),
            // --- Secure Boot ---
            ShowcaseStep(
                id: "device.buildsign",
                title: "Build + sign the chain",
                rationale: "Builds the secure-boot bootloader + app and HSM-signs them with both keys (RSA-3072), so either boot signer can verify the image. Stamps the anti-rollback secure_version.",
                script: "3-build-sign.sh",
                mode: .terminal,
                terminalHint: "Two-key sign: insert the main token (PIN), then swap to the backup token (PIN)."
            ),
            ShowcaseStep(
                id: "device.flash",
                title: "Flash + enable Secure Boot",
                rationale: "Flashes the signed chain and burns BOTH key digests (DIGEST0 + DIGEST1) + SECURE_BOOT_EN. From here only signed firmware boots, and either token can. Irreversible. (Must happen BEFORE the seal — it needs eFuse reads that Secure Download Mode would block.)",
                script: "4-flash-enable-secureboot.sh",
                args: [.port, .literal("--keys"), .literal("mainToken,backupToken"), .literal("--yes-burn")],
                mode: .terminal,
                terminalHint: "espefuse will ask you to type BURN to confirm the digest + enable burns."
            ),
            // --- final seal (LAST: crypt-count max + disable manual encrypt + secure download) ---
            ShowcaseStep(
                id: "device.seal.rehearse",
                title: "Release seal — rehearse",
                rationale: "Dry-run the final seal on a virtual eFuse and read the live board's current fuse state. Nothing burned.",
                script: "6-release-seal.sh",
                args: [.port],
                mode: .inline
            ),
            ShowcaseStep(
                id: "device.seal",
                title: "Release seal + kill console (LAST)",
                rationale: "The point of no return: maxes the flash-encryption counter, disables manual encrypt, enables Secure Download Mode, and burns DIS_USB_SERIAL_JTAG — the last serial console. The cable can no longer read, dump, or reflash; signed+encrypted OTA is the only way in. Do this last, once everything above is verified.",
                script: "6-release-seal.sh",
                args: [.port, .literal("--kill-console"), .literal("--yes-burn")],
                mode: .terminal,
                terminalHint: "espefuse will ask you to type BURN. Do this on a FRESH unit — once sealed, espefuse is locked out for good."
            ),
        ]
    )

    // MARK: Phase 2 — Testing (read-only proofs)
    static let testing = ShowcaseArea(
        id: "testing",
        title: "2 · Testing",
        icon: "checkmark.seal",
        blurb: "Prove the device is locked down — read-only cable checks and an over-the-network attack. Nothing is burned or changed; run these anytime after provisioning.",
        steps: [
            ShowcaseStep(
                id: "device.verifyseal",
                title: "Verify seal (cable lockout)",
                rationale: "Proves the cable is locked out: eFuse read, flash read, and encrypt-write are all DENIED on a sealed board. Read-only and safe.",
                script: "verify-seal.sh",
                args: [.port],
                mode: .inline
            ),
            ShowcaseStep(
                id: "pentest.attack",
                title: "OTA attack test",
                rationale: "Fires 7 crafted bad firmware images at :8081 and confirms each is refused in-band (rollback, garbage, tampered body, bad signature, untrusted key…). The device never reboots.",
                script: "ota-attack-test.sh",
                args: [.host],
                mode: .inline,
                verdict: ShowcaseStep.attackTestVerdict
            ),
            ShowcaseStep(
                id: "pentest.attack.full",
                title: "OTA attack test — full signature path",
                rationale: "Signs a fresh higher-version base first so the signature-path attacks clear the version gate and hit the on-device RSA check.",
                script: "ota-attack-test.sh",
                args: [.host, .literal("--build-base")],
                mode: .terminal,
                terminalHint: "Enter the token PIN once (to sign the higher-version base).",
                verdict: ShowcaseStep.attackTestVerdict
            ),
        ]
    )

    // MARK: Phase 3 — Firmware updates (OTA)
    static let updates = ShowcaseArea(
        id: "updates",
        title: "3 · Firmware updates",
        icon: "arrow.down.circle",
        blurb: "After provisioning, the ONLY way to change firmware. Build + sign + deliver a signed, encrypted image over the network into the inactive slot, verified before activation.",
        steps: [
            ShowcaseStep(
                id: "ota.devicekeys",
                title: "Read device public keys",
                rationale: "Reads the device's own public keys off the serial boot log — the Ed25519 response-signing key and the X25519 ROM key — which the client needs to talk to it. They're derived on-chip from the eFuse HMAC root, so this is the only way to get them. Copies them to the clipboard as JSON; import via Settings › Import config.",
                script: "show-device-keys.sh",
                args: [.port],
                mode: .terminal,
                terminalHint: "Press RESET on the board when prompted (or `pip3 install pyserial` for an automatic reset)."
            ),
            ShowcaseStep(
                id: "ota.storecreds",
                title: "Store credentials",
                rationale: "Saves the device IP (and, if given, Wi-Fi + supervisor key) in the macOS Keychain so the update commands need no arguments.",
                script: "store-creds.sh",
                args: [.host],
                mode: .inline
            ),
            ShowcaseStep(
                id: "ota.update",
                title: "One-pass OTA update",
                rationale: "Builds + signs the app and streams it to the running device — into the inactive slot, verified before activation. Signs with both keys by default so either token can OTA-recover it. The only firmware-change path on a sealed board.",
                script: "ota-update.sh",
                args: [.host],
                mode: .terminal,
                terminalHint: "Two-key sign: insert the main token (PIN), then swap to the backup token (PIN); delivery is automatic."
            ),
            ShowcaseStep(
                id: "ota.push",
                title: "Push an already-signed image",
                rationale: "Sends the last signed image over TCP without rebuilding — no PIN needed.",
                script: "ota-push.sh",
                args: [.host],
                mode: .inline
            ),
        ]
    )
}
