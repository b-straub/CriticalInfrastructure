import Foundation
import XCTest
@testable import CriticalInfraKit

/// Verifies the showcase catalog resolves to the exact `provision/*.sh` command lines and that
/// the inline/terminal/manual classification is self-consistent (no interactive-gated script is
/// ever marked `.inline`).
final class ShowcaseCatalogTests: XCTestCase {

    private var allSteps: [ShowcaseStep] { ShowcaseCatalog.areas.flatMap(\.steps) }

    private func step(_ id: String) -> ShowcaseStep {
        guard let s = allSteps.first(where: { $0.id == id }) else {
            fatalError("no showcase step with id \(id)")
        }
        return s
    }

    // MARK: resolution

    func testResolveInlineVerifySeal() throws {
        let cfg = DeviceConfig(host: "192.168.178.133", repoPath: "/Users/x/CriticalInfrastructure")
        let inv = resolveShowcaseStep(step("device.verifyseal"), repoPath: cfg.repoPath, config: cfg, port: "/dev/cu.usbmodem1")
        let inv2 = try XCTUnwrap(inv)
        XCTAssertEqual(inv2.scriptPath, "/Users/x/CriticalInfrastructure/provision/verify-seal.sh")
        XCTAssertEqual(inv2.args, ["--port", "/dev/cu.usbmodem1"])
        XCTAssertEqual(inv2.display, "provision/verify-seal.sh --port /dev/cu.usbmodem1")
    }

    func testResolveOmitsPortWhenNoneSelected() throws {
        let cfg = DeviceConfig(repoPath: "/r")
        let inv = try XCTUnwrap(resolveShowcaseStep(step("device.seal.rehearse"), repoPath: cfg.repoPath, config: cfg, port: nil))
        // No --port → the script auto-detects the board itself.
        XCTAssertEqual(inv.args, [])
        XCTAssertEqual(inv.display, "provision/6-release-seal.sh")
    }

    func testResolveHostFromConfig() throws {
        let cfg = DeviceConfig(host: "10.0.0.5", repoPath: "/r")
        let inv = try XCTUnwrap(resolveShowcaseStep(step("pentest.attack"), repoPath: cfg.repoPath, config: cfg, port: nil))
        XCTAssertEqual(inv.args, ["--host", "10.0.0.5"])
        XCTAssertEqual(inv.display, "provision/ota-attack-test.sh --host 10.0.0.5")
    }

    func testResolveOmitsHostWhenEmpty() throws {
        let cfg = DeviceConfig(host: "  ", repoPath: "/r")
        let inv = try XCTUnwrap(resolveShowcaseStep(step("pentest.attack"), repoPath: cfg.repoPath, config: cfg, port: nil))
        // Empty host → no --host; the script falls back to the Keychain device IP.
        XCTAssertEqual(inv.args, [])
    }

    func testResolveLiteralsAndOrder() throws {
        let cfg = DeviceConfig(host: "1.2.3.4", repoPath: "/r")
        let inv = try XCTUnwrap(resolveShowcaseStep(step("device.seal"), repoPath: cfg.repoPath, config: cfg, port: "/dev/cu.x"))
        XCTAssertEqual(inv.args, ["--port", "/dev/cu.x", "--kill-console", "--yes-burn"])
    }

    func testTrailingSlashRepoPathNormalized() throws {
        let cfg = DeviceConfig(repoPath: "/r/")
        let inv = try XCTUnwrap(resolveShowcaseStep(step("device.verifyseal"), repoPath: cfg.repoPath, config: cfg, port: nil))
        XCTAssertEqual(inv.scriptPath, "/r/provision/verify-seal.sh")
    }

    func testManualStepDoesNotResolve() {
        let cfg = DeviceConfig(repoPath: "/r")
        XCTAssertNil(resolveShowcaseStep(step("keys.keygen"), repoPath: cfg.repoPath, config: cfg, port: nil))
        XCTAssertNil(step("keys.keygen").script)
    }

    // MARK: classification safety

    /// The scripts that are safe to run headless (no token PIN, no espefuse BURN, no `read -p`).
    private static let knownSafeInlineScripts: Set<String> = [
        "1-enroll-key.sh",       // reads the on-card public object only
        "2-efuse-harden.sh",     // inline only in the DRY-RUN form (no --yes-burn) — checked below
        "6-release-seal.sh",     // inline only in the DRY-RUN form (no --yes-burn) — checked below
        "verify-seal.sh",        // read-only
        "ota-attack-test.sh",    // inline only without --build-base — checked below
        "store-creds.sh",
        "ota-push.sh",           // image already signed, no PIN
    ]

    func testInlineStepsAreInKnownSafeSet() {
        for s in allSteps where s.mode == .inline {
            let script = try! XCTUnwrap(s.script, "\(s.id) is .inline but has no script")
            XCTAssertTrue(Self.knownSafeInlineScripts.contains(script),
                          "\(s.id) runs \(script) inline but it is not in the known-safe set")
        }
    }

    /// No `.inline` step may carry a gate flag that requires interaction.
    func testInlineStepsHaveNoInteractiveFlags() {
        let gateFlags: Set<String> = ["--yes-burn", "--build-base"]
        for s in allSteps where s.mode == .inline {
            for case .literal(let f) in s.args {
                XCTAssertFalse(gateFlags.contains(f), "\(s.id) is .inline but passes \(f)")
            }
        }
    }

    func testManualStepsHaveNoScript() {
        for s in allSteps where s.mode == .manual {
            XCTAssertNil(s.script, "\(s.id) is .manual but has a script")
        }
    }

    func testTerminalStepsHaveScript() {
        for s in allSteps where s.mode == .terminal {
            XCTAssertNotNil(s.script, "\(s.id) is .terminal but has no script")
        }
    }

    func testStepIDsUnique() {
        let ids = allSteps.map(\.id)
        XCTAssertEqual(ids.count, Set(ids).count, "duplicate showcase step ids")
    }

    func testThreePhases() {
        XCTAssertEqual(ShowcaseCatalog.areas.map(\.id), ["provision", "testing", "updates"])
    }

    /// Phase 1 (provisioning) must be strictly ordered: every irreversible burn is immediately
    /// preceded by its rehearse, and the release seal is the very last step.
    func testProvisioningOrderRehearseBeforeBurn() {
        let ids = ShowcaseCatalog.provisioning.steps.map(\.id)
        func idx(_ s: String) -> Int { ids.firstIndex(of: s)! }
        XCTAssertLessThan(idx("device.harden.rehearse"), idx("device.harden.burn"))
        XCTAssertLessThan(idx("device.seal.rehearse"), idx("device.seal"))
        XCTAssertLessThan(idx("device.flash"), idx("device.seal"))          // Secure Boot before the seal
        XCTAssertEqual(ids.last, "device.seal")                              // seal is the point of no return
    }

    // MARK: verdict mapping

    func testParseRolesResponse() {
        XCTAssertEqual(Command.parseRolesResponse("No roles found"), [])
        XCTAssertNil(Command.parseRolesResponse("Signature verification failed or Unknown Role"))
        XCTAssertEqual(
            Command.parseRolesResponse("ROLES:Admin@Mac:03abc,Observer@iPad-01:02def,"),
            [Command.DeviceRole(name: "Admin", label: "Mac"),
             Command.DeviceRole(name: "Observer", label: "iPad-01")]
        )
        // legacy unlabeled entry
        XCTAssertEqual(
            Command.parseRolesResponse("ROLES:Admin:03abc,"),
            [Command.DeviceRole(name: "Admin", label: "")]
        )
    }

    func testGenericVerdict() {
        XCTAssertEqual(ShowcaseStep.exitZeroPass(0), .pass)
        XCTAssertEqual(ShowcaseStep.exitZeroPass(1), .fail)
    }

    func testAttackTestVerdict() {
        XCTAssertEqual(ShowcaseStep.attackTestVerdict(0), .pass)
        XCTAssertEqual(ShowcaseStep.attackTestVerdict(1), .fail)
        if case .warn = ShowcaseStep.attackTestVerdict(2) {} else {
            XCTFail("exit 2 should map to .warn")
        }
    }

    func testDeviceConfigDecodesLegacyJSONWithoutRepoPath() throws {
        // Old persisted config had no repoPath — must still decode (not wipe the user's settings).
        let legacy = #"{"host":"1.2.3.4","port":8080,"espX25519PubHex":"aa","espSigPubHex":"bb"}"#
        let cfg = try JSONDecoder().decode(DeviceConfig.self, from: Data(legacy.utf8))
        XCTAssertEqual(cfg.host, "1.2.3.4")
        XCTAssertEqual(cfg.repoPath, "")
    }
}
