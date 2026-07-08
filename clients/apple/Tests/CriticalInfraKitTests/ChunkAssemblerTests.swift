import Foundation
import XCTest
@testable import CriticalInfraKit

/// Verifies datagram reassembly matches the firmware's `[total][seq][payload]`
/// framing, including out-of-order arrival and malformed frames.
final class ChunkAssemblerTests: XCTestCase {

    private func frame(total: UInt8, seq: UInt8, _ s: String) -> Data {
        var d = Data([total, seq])
        d.append(Data(s.utf8))
        return d
    }

    private func string(_ d: Data?) -> String? {
        d.flatMap { String(data: $0, encoding: .utf8) }
    }

    func testSingleChunk() throws {
        let a = ChunkAssembler()
        XCTAssertEqual(string(try a.add(frame(total: 1, seq: 0, "solo"))), "solo")
    }

    func testReassemblesInOrder() throws {
        let a = ChunkAssembler()
        XCTAssertNil(try a.add(frame(total: 3, seq: 0, "AAA")))
        XCTAssertNil(try a.add(frame(total: 3, seq: 1, "BBB")))
        XCTAssertEqual(string(try a.add(frame(total: 3, seq: 2, "CCC"))), "AAABBBCCC")
    }

    func testReassemblesOutOfOrder() throws {
        let a = ChunkAssembler()
        XCTAssertNil(try a.add(frame(total: 2, seq: 1, "world")))
        XCTAssertEqual(string(try a.add(frame(total: 2, seq: 0, "hello"))), "helloworld")
    }

    func testTooShortRejected() {
        let a = ChunkAssembler()
        XCTAssertThrowsError(try a.add(Data([0x01]))) { XCTAssertEqual($0 as? TransportError, .malformedFrame) }
    }

    func testSeqOutOfRangeRejected() {
        let a = ChunkAssembler()
        XCTAssertThrowsError(try a.add(frame(total: 2, seq: 2, "x"))) { XCTAssertEqual($0 as? TransportError, .malformedFrame) }
    }
}
