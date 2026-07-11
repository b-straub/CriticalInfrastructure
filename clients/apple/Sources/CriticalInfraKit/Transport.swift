import Foundation

/// One request/response exchange of a command envelope, independent of the link. Both the UDP
/// (`UdpTransport`) and BLE (`BleTransport`) transports conform; `DeviceClient` depends only on
/// this. The envelope is end-to-end encrypted+signed, so the link itself need not be trusted.
public protocol DeviceTransport: Sendable {
    /// Send `payload` and return the device's (reassembled) reply, or throw `TransportError`.
    func sendReceive(_ payload: Data, timeout: TimeInterval) async throws -> Data
}

// UdpTransport already exposes exactly this method (UdpTransport.swift) — declare conformance.
extension UdpTransport: DeviceTransport {}

/// Splits a payload into `[total: UInt8][seq: UInt8][payload…]` frames of at most `maxChunk`
/// payload bytes each — the outbound counterpart of `ChunkAssembler`. BLE needs this because a
/// GATT write can't exceed the negotiated ATT MTU (~244 B), so a ~420–800 B request is chunked;
/// the firmware reassembles by `seq`. (UDP sends the request in one datagram and never used this.)
enum FrameChunker {
    static func chunk(_ payload: Data, maxChunk: Int) -> [Data] {
        precondition(maxChunk > 0, "maxChunk must be positive")
        // One empty frame keeps the framing well-formed for an empty payload.
        if payload.isEmpty { return [Data([1, 0])] }
        let total = (payload.count + maxChunk - 1) / maxChunk
        precondition(total <= 255, "payload too large to frame in one exchange")
        var frames: [Data] = []
        var seq = 0
        var idx = payload.startIndex
        while idx < payload.endIndex {
            let end = payload.index(idx, offsetBy: maxChunk, limitedBy: payload.endIndex) ?? payload.endIndex
            var frame = Data([UInt8(total), UInt8(seq)])
            frame.append(payload[idx..<end])
            frames.append(frame)
            idx = end
            seq += 1
        }
        return frames
    }
}
