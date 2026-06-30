import Foundation

/// Per-message parameters bound into the key schedule (draft §4.4, payload_info).
///
/// Wire layout (each element is also `frame()`d individually when fed to the KDF):
/// ```
/// aead_id(uint16) | segment_max(uint32) | kdf_id(uint16) | snap_id(uint16) |
/// nonce_mode(uint8) | epoch_length(uint8) | salt(32)
/// ```
public struct PayloadInfo: Equatable, Sendable {
	/// Nonce construction (draft Table 10).
	public enum NonceMode: UInt8, Equatable, Sendable {
		case random = 0x00
		case derived = 0x01
	}

	public var aeadID: UInt16
	public var segmentMax: UInt32
	public var kdfID: UInt16
	public var snapID: UInt16
	public var nonceMode: NonceMode
	/// `r ∈ [0, 63]`; each epoch covers `2^r` consecutive segments.
	public var epochLength: UInt8
	/// Per-content salt, exactly 32 octets.
	public var salt: [UInt8]

	public init(
		aeadID: UInt16,
		segmentMax: UInt32,
		kdfID: UInt16,
		snapID: UInt16,
		nonceMode: NonceMode,
		epochLength: UInt8,
		salt: [UInt8]
	) {
		self.aeadID = aeadID
		self.segmentMax = segmentMax
		self.kdfID = kdfID
		self.snapID = snapID
		self.nonceMode = nonceMode
		self.epochLength = epochLength
		self.salt = salt
	}

	public enum ValidationError: Error, Equatable {
		case saltLength(Int)
		case segmentMaxNotPowerOfTwo(UInt32)
		case segmentMaxTooSmall(UInt32)
		case epochLengthOutOfRange(UInt8)
	}

	/// Validate the constraints from §4.4 / §4.5.2.
	public func validate() throws {
		guard salt.count == 32 else { throw ValidationError.saltLength(salt.count) }
		guard segmentMax >= 4096 else {
			throw ValidationError.segmentMaxTooSmall(segmentMax)
		}
		guard segmentMax & (segmentMax - 1) == 0 else {
			throw ValidationError.segmentMaxNotPowerOfTwo(segmentMax)
		}
		guard epochLength < 64 else {
			throw ValidationError.epochLengthOutOfRange(epochLength)
		}
	}

	/// The ordered list of elements the KDF frames individually as `info` (§4.5.1).
	var kdfInfoElements: [[UInt8]] {
		[
			Bytes.uint16(Int(aeadID)),
			Bytes.uint32(segmentMax),
			Bytes.uint16(Int(kdfID)),
			Bytes.uint16(Int(snapID)),
			[nonceMode.rawValue],
			[epochLength],
			salt,
		]
	}

	/// The concatenated on-the-wire encoding (44 octets), unframed.
	public var wireBytes: [UInt8] {
		kdfInfoElements.flatMap { $0 }
	}
}
