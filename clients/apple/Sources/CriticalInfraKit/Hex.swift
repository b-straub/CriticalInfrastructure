import Foundation

extension Data {
    /// Parse a lowercase/uppercase hex string. Returns nil on odd length or a
    /// non-hex character (mirrors the firmware's strict `from_str_radix` parsing).
    init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = Data.nibble(chars[i]), let lo = Data.nibble(chars[i + 1]) else {
                return nil
            }
            out.append(hi << 4 | lo)
            i += 2
        }
        self = out
    }

    /// Lowercase hex, matching the firmware's `{:02x}` formatting.
    var hexString: String {
        var s = String()
        s.reserveCapacity(count * 2)
        for b in self {
            s.append(Data.hexDigits[Int(b >> 4)])
            s.append(Data.hexDigits[Int(b & 0x0f)])
        }
        return s
    }

    private static let hexDigits = Array("0123456789abcdef")

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30            // 0-9
        case 0x61...0x66: return c - 0x61 + 10       // a-f
        case 0x41...0x46: return c - 0x41 + 10       // A-F
        default: return nil
        }
    }
}
