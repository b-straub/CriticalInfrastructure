import Foundation
import Network

public enum TransportError: Error, Equatable, CustomStringConvertible {
    case timeout
    case connection(String)
    case noData
    case malformedFrame

    public var description: String {
        switch self {
        case .timeout: return "No reply from device (timed out)"
        case .connection(let m): return "Connection error: \(m)"
        case .noData: return "Empty reply from device"
        case .malformedFrame: return "Malformed reply frame"
        }
    }
}

/// Reassembles a reply that the device sends as one or more framed datagrams,
/// each `[total: UInt8][seq: UInt8][payload...]`. The device fragments because
/// its stack (smoltcp) does not IPv4-TX-fragment; this makes the UDP transport
/// size-agnostic like TCP. Feed datagrams in any order; `add` returns the full
/// payload once all `total` chunks have arrived.
final class ChunkAssembler: @unchecked Sendable {
    private var chunks: [Int: Data] = [:]
    private var total: Int?

    func add(_ datagram: Data) throws -> Data? {
        guard datagram.count >= 2 else { throw TransportError.malformedFrame }
        let base = datagram.startIndex
        let t = Int(datagram[base])
        let seq = Int(datagram[base + 1])
        guard t >= 1, seq < t else { throw TransportError.malformedFrame }
        total = t
        chunks[seq] = Data(datagram[(base + 2)...])
        guard chunks.count == t else { return nil }

        var full = Data()
        for i in 0..<t {
            guard let part = chunks[i] else { return nil }
            full.append(part)
        }
        return full
    }
}

/// One request/response exchange over UDP via Network.framework.
///
/// A fresh `NWConnection` per call keeps request/response correlation trivially
/// clean: a stray datagram from an earlier request lands on a since-closed local
/// port. The request is a single datagram; the reply may be several framed chunks
/// which are reassembled here. The whole exchange resolves exactly once — on the
/// first of {complete reply, failure, timeout} — and always cancels the socket.
public final class UdpTransport: @unchecked Sendable {
    private let host: NWEndpoint.Host
    private let port: NWEndpoint.Port
    private let queue = DispatchQueue(label: "criticalinfra.udp")

    public init(host: String, port: UInt16) {
        self.host = NWEndpoint.Host(host)
        self.port = NWEndpoint.Port(rawValue: port)
            ?? NWEndpoint.Port(rawValue: AppConstants.defaultPort)!
    }

    public func sendReceive(_ payload: Data, timeout: TimeInterval) async throws -> Data {
        let conn = NWConnection(host: host, port: port, using: .udp)
        let once = ResumeOnce()
        // All NWConnection callbacks and the timeout run on the serial `queue`,
        // so this reassembler is only ever touched by one thread at a time.
        let assembler = ChunkAssembler()

        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            // Overall deadline: covers connect + send + all reply chunks.
            queue.asyncAfter(deadline: .now() + timeout) {
                if once.take() {
                    conn.cancel()
                    cont.resume(throwing: TransportError.timeout)
                }
            }

            func receiveNext() {
                conn.receiveMessage { data, _, _, recvErr in
                    if let recvErr {
                        if once.take() {
                            conn.cancel()
                            cont.resume(throwing: TransportError.connection("\(recvErr)"))
                        }
                        return
                    }
                    guard let data, !data.isEmpty else {
                        if once.take() {
                            conn.cancel()
                            cont.resume(throwing: TransportError.noData)
                        }
                        return
                    }
                    do {
                        if let full = try assembler.add(data) {
                            if once.take() {
                                conn.cancel()
                                cont.resume(returning: full)
                            }
                        } else {
                            receiveNext() // more chunks expected
                        }
                    } catch {
                        if once.take() {
                            conn.cancel()
                            cont.resume(throwing: error)
                        }
                    }
                }
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: payload, completion: .contentProcessed { sendErr in
                        if let sendErr {
                            if once.take() {
                                conn.cancel()
                                cont.resume(throwing: TransportError.connection("\(sendErr)"))
                            }
                            return
                        }
                        receiveNext()
                    })
                case .failed(let err):
                    if once.take() {
                        conn.cancel()
                        cont.resume(throwing: TransportError.connection("\(err)"))
                    }
                default:
                    break
                }
            }

            conn.start(queue: queue)
        }
    }
}

/// Resume-once guard: the reply, a failure, and the timeout can race on `queue`;
/// only the first caller is allowed to resume the continuation.
private final class ResumeOnce: @unchecked Sendable {
    private var done = false
    private let lock = NSLock()
    func take() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
