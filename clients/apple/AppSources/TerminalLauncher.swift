#if os(macOS)
import AppKit
import Foundation
import CriticalInfraKit

/// Launches an interactive `provision/*.sh` step in a real terminal (so the token PIN, the
/// `espefuse` BURN confirmation, and the backup-token `read -p` prompts all work), plus a
/// copy-to-clipboard fallback. macOS-only.
enum TerminalLauncher {

    /// Open Terminal.app running `invocation` from the repo root. Uses a temporary executable
    /// `.command` file opened via `NSWorkspace`, which starts a TTY WITHOUT sending Apple Events
    /// — so it needs no Automation (TCC) grant and no `NSAppleEventsUsageDescription`.
    static func run(_ inv: ScriptInvocation, repoPath: String) {
        let command = ([shellQuote(inv.scriptPath)] + inv.args.map(shellQuote)).joined(separator: " ")
        let body = """
        #!/bin/bash
        cd \(shellQuote(repoPath))
        echo "+ provision/\(inv.display)"
        \(command)
        status=$?
        echo
        echo "[exit $status] — press Return to close."
        read -r _
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("showcase-\(UUID().uuidString).command")
        do {
            try body.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            NSWorkspace.shared.open(url)
        } catch {
            // Fall back to copying the command so the user can run it by hand.
            copyToClipboard(inv.display)
        }
    }

    /// Put the repo-relative command line on the clipboard.
    static func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
#endif
