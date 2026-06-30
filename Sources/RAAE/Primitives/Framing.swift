import Foundation

/// Length-prefixed framing for KDF inputs (draft §4.3).
///
/// ```
/// frame(x):
///     if len(x) <= 0xFFFE:  return uint16(len(x)) || x
///     else:                 return uint16(0xFFFF) || LH(x)
///
/// encode(x1, ..., xn) = frame(x1) || ... || frame(xn)
/// ```
///
/// The over-large path (`len(x) > 0xFFFE`) substitutes an `Nh`-octet digest `LH(x)`
/// produced by the KDF's native primitive. Because that digest depends on the chosen
/// KDF, framing is parameterized by a `longHash` closure supplied by the KDF.
enum Framing {
	/// The reserved length marking an over-large field whose value is replaced by `LH(x)`.
	static let escapeLength = 0xFFFF

	/// Maximum literally-framed field length.
	static let maxLiteralLength = 0xFFFE

	/// `frame(x)` — length-prefix a single field.
	static func frame(_ field: [UInt8], longHash: ([UInt8]) -> [UInt8]) -> [UInt8] {
		if field.count <= maxLiteralLength {
			return Bytes.uint16(field.count) + field
		}
		return Bytes.uint16(escapeLength) + longHash(field)
	}

	/// `encode(x1, ..., xn)` — concatenation of the framed fields, in order.
	static func encode(_ fields: [[UInt8]], longHash: ([UInt8]) -> [UInt8]) -> [UInt8] {
		var out: [UInt8] = []
		for field in fields {
			out += frame(field, longHash: longHash)
		}
		return out
	}
}
