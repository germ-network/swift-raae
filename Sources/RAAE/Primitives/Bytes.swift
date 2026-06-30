import Foundation

/// Big-endian fixed-width integer encodings used throughout the wire format and the
/// KDF framing (`uint16`/`uint32` in the draft, §2.2).
enum Bytes {
	/// `uint16(x)` — big-endian 2-octet encoding.
	static func uint16(_ value: Int) -> [UInt8] {
		precondition(value >= 0 && value <= 0xFFFF, "uint16 out of range: \(value)")
		return [UInt8(value >> 8), UInt8(value & 0xFF)]
	}

	/// `uint32(x)` — big-endian 4-octet encoding.
	static func uint32(_ value: UInt32) -> [UInt8] {
		[
			UInt8(value >> 24 & 0xFF),
			UInt8(value >> 16 & 0xFF),
			UInt8(value >> 8 & 0xFF),
			UInt8(value & 0xFF),
		]
	}

	/// `uint64(x)` — big-endian 8-octet encoding.
	static func uint64(_ value: UInt64) -> [UInt8] {
		(0..<8).reversed().map { UInt8(value >> (UInt64($0) * 8) & 0xFF) }
	}

	/// ASCII bytes of a label / protocol identifier.
	static func ascii(_ string: String) -> [UInt8] {
		Array(string.utf8)
	}
}
