import Foundation

/// High-level client: sign + send + verify one command.
///
/// The command is signed **once** (one Touch ID prompt) and the resulting
/// datagram is retried on the wire — so a lost packet doesn't re-prompt. Because
/// the same timestamp is reused across retries, a retry after the device already
/// accepted the command (only the reply was lost) comes back as a signed
/// "Replay Attack Detected"; that's rare on a LAN and still authenticated.
public actor DeviceClient {
    public let config: DeviceConfig
    private let transport: UdpTransport
    private let signer: CommandSigner

    public init(config: DeviceConfig, signer: CommandSigner) {
        self.config = config
        self.transport = UdpTransport(host: config.host, port: config.port)
        self.signer = signer
    }

    private static let maxAttempts = 2
    private static let retryDelayNanos: UInt64 = 300_000_000
    // Generous: a role command makes the device do TWO software P-256 verifies
    // (the role signature + re-verifying the supervisor certificate every time),
    // which is slow on the ESP32. Too tight a timeout causes a retransmit that the
    // device then (correctly) flags as a replay.
    private static let recvTimeout: TimeInterval = 5.0

    /// The device's replay-rejection message (firmware `protocol.rs`).
    private static let replayRejected = "Replay Attack Detected"

    /// Send `command`, returning the device's verified message or a user-facing
    /// error string.
    public func send(_ command: String) async -> String {
        let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)

        // Sign once (Touch ID here); reuse the datagram across wire retries.
        let envelope: CommandEnvelope
        do {
            envelope = try Envelope.encrypt(
                command: command,
                espX25519PubHex: config.espX25519PubHex,
                timestamp: timestamp,
                sign: { try signer.sign($0) }
            )
        } catch let error as EnvelopeError {
            return error.description
        } catch {
            return "Signing cancelled or failed: \(error.localizedDescription)"
        }

        let payloadData = Data(envelope.payload.utf8)
        for attempt in 1...Self.maxAttempts {
            do {
                let reply = try await transport.sendReceive(payloadData, timeout: Self.recvTimeout)
                guard let text = String(data: reply, encoding: .utf8) else {
                    if attempt == Self.maxAttempts { break }
                    try? await Task.sleep(nanoseconds: Self.retryDelayNanos)
                    continue
                }
                let message = try Envelope.verifyResponse(
                    text,
                    ephemeralPrivateKey: envelope.ephemeralPrivateKey,
                    espSigPubHex: config.espSigPubHex,
                    timestamp: timestamp
                )
                // A replay rejection on our OWN retransmit (attempt > 1) is not an
                // attack — the device already accepted the command and its first
                // (valid) reply was lost or slow. Report that, not "replay".
                if attempt > 1 && message == Self.replayRejected {
                    return "Command was accepted (the device's first reply was lost). Send again for a fresh reading."
                }
                return message
            } catch EnvelopeError.signatureInvalid {
                return "Rejected: response signature INVALID (possible MITM)."
            } catch {
                // Timeout / stray datagram / bad frame — retry the same datagram.
                if attempt == Self.maxAttempts { break }
                try? await Task.sleep(nanoseconds: Self.retryDelayNanos)
            }
        }
        return "Could not reach the device. Check the IP / keys in settings, then retry."
    }
}
