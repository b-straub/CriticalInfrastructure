#if os(macOS)
import Foundation
import CriticalInfraKit

/// Runs an inline (headless-safe) `provision/*.sh` step via `Process`, streaming its combined
/// stdout+stderr to the UI and deriving a `Verdict` from the exit code. macOS-only — `Process`
/// and shell tooling don't exist on iOS.
///
/// Only `.inline` steps are ever run here; anything with an interactive gate (token PIN,
/// `espefuse` BURN confirm, backup-token `read -p`) goes through `TerminalLauncher` instead — a
/// pipe can't answer those prompts.
@MainActor
@Observable
final class ShowcaseController {
    /// The step currently running, or `nil` when idle.
    private(set) var runningStepID: String?
    /// The id of the step whose result (`output` + `verdict`) is currently shown.
    private(set) var resultStepID: String?
    /// Combined stdout+stderr of the current/last run, appended live.
    private(set) var output: String = ""
    private(set) var verdict: Verdict = .unknown

    var isRunning: Bool { runningStepID != nil }

    private var process: Process?

    /// GUI apps launch with a minimal PATH; the scripts (and `lib.sh`'s espsecure lookup) need
    /// Homebrew + the standard bins. Prepend them so `need <tool>` checks resolve.
    private static let pathPrefix = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

    /// Run a resolved invocation inline. Streams output into `output`; on exit sets `verdict`.
    func runInline(_ inv: ScriptInvocation, stepID: String, verdictMap: @escaping @Sendable (Int32) -> Verdict) {
        guard runningStepID == nil else { return }
        runningStepID = stepID
        resultStepID = stepID
        output = ""
        verdict = .unknown

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [inv.scriptPath] + inv.args

        var env = ProcessInfo.processInfo.environment
        let existing = env["PATH"] ?? ""
        env["PATH"] = existing.isEmpty ? Self.pathPrefix : "\(Self.pathPrefix):\(existing)"
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        self.process = process

        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty, let chunk = String(data: data, encoding: .utf8) else { return }
            Task { @MainActor [weak self] in self?.output += chunk }
        }

        process.terminationHandler = { proc in
            let status = proc.terminationStatus
            Task { @MainActor [weak self] in
                guard let self else { return }
                pipe.fileHandleForReading.readabilityHandler = nil
                self.verdict = verdictMap(status)
                self.runningStepID = nil
                self.process = nil
            }
        }

        do {
            try process.run()
        } catch {
            pipe.fileHandleForReading.readabilityHandler = nil
            output += "\nfailed to launch: \(error.localizedDescription)\n"
            verdict = .fail
            runningStepID = nil
            self.process = nil
        }
    }

    /// Terminate a long-running inline step (e.g. the attack test reboots the board ~7×).
    func cancel() {
        process?.terminate()
    }

    /// Forget the last result (so a card collapses its output view).
    func clearResult(for stepID: String) {
        if resultStepID == stepID {
            resultStepID = nil
            output = ""
            verdict = .unknown
        }
    }
}
#endif
