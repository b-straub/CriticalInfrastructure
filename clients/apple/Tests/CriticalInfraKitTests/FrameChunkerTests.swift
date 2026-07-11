import Foundation
import XCTest
@testable import CriticalInfraKit

/// Verifies the outbound `FrameChunker` produces `[total][seq][payload]` frames that the inbound
/// `ChunkAssembler` reassembles back to the original — the BLE request path (chunk on write) and
/// the reply path (reassemble on notify) must agree on the framing, and match the firmware.
final class FrameChunkerTests: XCTestCase {

    private func roundTrip(_ payload: Data, maxChunk: Int) throws -> Data? {
        let frames = FrameChunker.chunk(payload, maxChunk: maxChunk)
        let asm = ChunkAssembler()
        var result: Data?
        for f in frames { result = try asm.add(f) }
        return result
    }

    func testSingleChunk() throws {
        let payload = Data("WHOAMI".utf8)
        let frames = FrameChunker.chunk(payload, maxChunk: 240)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0][frames[0].startIndex], 1)      // total = 1
        XCTAssertEqual(frames[0][frames[0].startIndex + 1], 0)  // seq = 0
        XCTAssertEqual(try roundTrip(payload, maxChunk: 240), payload)
    }

    func testMultiChunkRoundTrip() throws {
        // A realistic ~800-byte envelope over a 240-byte BLE MTU -> 4 chunks.
        let payload = Data((0..<800).map { UInt8($0 % 251) })
        let frames = FrameChunker.chunk(payload, maxChunk: 240)
        XCTAssertEqual(frames.count, 4)
        XCTAssertEqual(Int(frames[0][frames[0].startIndex]), 4)  // total on every frame
        XCTAssertEqual(try roundTrip(payload, maxChunk: 240), payload)
    }

    func testExactMultipleBoundary() throws {
        let payload = Data(repeating: 0xAB, count: 480)          // exactly 2 * 240
        let frames = FrameChunker.chunk(payload, maxChunk: 240)
        XCTAssertEqual(frames.count, 2)
        XCTAssertEqual(try roundTrip(payload, maxChunk: 240), payload)
    }

    func testMaxSizeResponse() throws {
        // The firmware reply cap is heapless::String<2560> -> 11 chunks at 240.
        let payload = Data((0..<2560).map { UInt8($0 & 0xff) })
        let frames = FrameChunker.chunk(payload, maxChunk: 240)
        XCTAssertEqual(frames.count, 11)
        XCTAssertEqual(try roundTrip(payload, maxChunk: 240), payload)
    }

    func testEmptyPayloadIsWellFormed() throws {
        let frames = FrameChunker.chunk(Data(), maxChunk: 240)
        XCTAssertEqual(frames.count, 1)
        // Reassembles to empty data (total=1, seq=0, no payload).
        XCTAssertEqual(try roundTrip(Data(), maxChunk: 240), Data())
    }

    func testFramesCarryCorrectSeq() {
        let payload = Data(repeating: 0x01, count: 500)
        let frames = FrameChunker.chunk(payload, maxChunk: 200)   // 3 frames
        for (i, f) in frames.enumerated() {
            XCTAssertEqual(Int(f[f.startIndex + 1]), i, "seq mismatch at frame \(i)")
            XCTAssertLessThanOrEqual(f.count - 2, 200, "payload exceeds maxChunk")
        }
    }
}
