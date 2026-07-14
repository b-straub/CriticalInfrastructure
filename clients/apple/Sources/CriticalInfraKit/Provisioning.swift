import Foundation

/// Supervisor-side provisioning: certify a new role's key and build its
/// `ADD_ROLE` command. The device stores the role with the supervisor's
/// certificate and re-verifies it on every command by that role (RAM-tamper
/// guard), so the cert must be signed by the supervisor key.
public enum Provisioning {
    /// Build `ADD_ROLE <role> <newPublicKeyHex> <certSigHex> <device>`, where the
    /// supervisor signs the certificate `ROLE:<role>;PUBKEY:<newPublicKeyHex>`.
    /// The device label is REQUIRED (the firmware rejects unlabeled grants); it is
    /// metadata outside the certificate (the supervisor-signed command
    /// authenticates it) so existing certificates stay valid.
    ///
    /// Prompts Touch ID once here (the certificate). The returned command is then
    /// sent via `DeviceClient(signer: supervisor)`, which signs the command itself
    /// (a second Touch ID). Both signatures are the supervisor's.
    public static func addRoleCommand(
        role: String,
        newPublicKeyHex: String,
        supervisor: CommandSigner,
        device: String
    ) throws -> String {
        let cert = Data("ROLE:\(role);PUBKEY:\(newPublicKeyHex)".utf8)
        let certSig = try supervisor.sign(cert)
        return Command.addRole(
            name: role, pubkeyHex: newPublicKeyHex, certSigHex: certSig.hexString, device: device
        )
    }
}
