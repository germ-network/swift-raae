import Crypto
import Foundation

/// A segment's position: its index and whether it is the final segment (§4.4).
public struct SegmentPosition: Equatable, Sendable {
	public var index: UInt64
	public var isFinal: Bool

	public init(index: UInt64, isFinal: Bool) {
		self.index = index
		self.isFinal = isFinal
	}
}

/// Per-segment encryption/decryption (draft §4.4.2 AAD + §4.8), for both the random and
/// derived nonce modes. Derived mode binds the index/is_final into the nonce rather than
/// the AAD.
public enum Segment {
	public enum SegmentError: Error, Equatable {
		/// Derived nonce mode needs `Nn >= 8` to hold `(i<<1)|is_final`.
		case nonceTooShortForDerivedMode(Int)
		/// Derived-mode operation attempted without a `nonce_base` in the schedule.
		case missingNonceBase
	}

	/// `segment_aad(i, is_final, A_i)` for the random nonce mode (§4.4.2, Table 2).
	///
	/// `kdf` supplies the framing's over-large-field digest (`LH`); it matters only when
	/// `associatedData` exceeds 65534 octets, but omitting it there would silently
	/// collide distinct values, so it is required.
	public static func aadRandomMode(
		position: SegmentPosition, associatedData: [UInt8], kdf: KeyDerivation
	) -> [UInt8] {
		var elements: [[UInt8]] = [
			Label.aadLabel,
			Bytes.uint64(position.index),
			[position.isFinal ? 1 : 0],
		]
		if !associatedData.isEmpty {
			elements.append(associatedData)
		}
		return Framing.encode(elements, longHash: kdf.longHash)
	}

	/// `segment_aad(i, is_final, A_i)` for derived nonce mode (§4.4.2, Table 2): index
	/// and finality are bound in the nonce, so the AAD is empty unless `A_i` is present.
	public static func aadDerivedMode(associatedData: [UInt8], kdf: KeyDerivation) -> [UInt8] {
		if associatedData.isEmpty { return [] }
		return Framing.encode([Label.aadLabel, associatedData], longHash: kdf.longHash)
	}

	/// `nonce(i) = nonce_base XOR ((i<<1)|is_final)` (§4.5.3): the value is encoded as a
	/// big-endian integer right-aligned to (and XORed into) the low octets of `nonce_base`.
	public static func derivedNonce(nonceBase: [UInt8], position: SegmentPosition) throws
		-> [UInt8]
	{
		guard nonceBase.count >= 8 else {
			throw SegmentError.nonceTooShortForDerivedMode(nonceBase.count)
		}
		let value = (position.index << 1) | (position.isFinal ? 1 : 0)
		var nonce = nonceBase
		let valueBytes = Bytes.uint64(value)  // 8 octets, big-endian
		for offset in 0..<8 {
			nonce[nonce.count - 1 - offset] ^= valueBytes[7 - offset]
		}
		return nonce
	}

	/// Encrypt one segment in random nonce mode, returning `(nonce, ciphertext = ct||tag)`.
	///
	/// The nonce is caller-supplied so tests can pin a vector's fixed nonce; production
	/// random-mode callers pass a freshly generated `Nn`-octet nonce.
	public static func encryptRandom(
		schedule: PayloadSchedule,
		position: SegmentPosition,
		associatedData: [UInt8],
		plaintext: [UInt8],
		nonce: [UInt8]
	) throws -> (nonce: [UInt8], ciphertext: [UInt8]) {
		let key = schedule.segmentKey(index: position.index)
		let aad = aadRandomMode(
			position: position, associatedData: associatedData, kdf: schedule.kdf)
		let ct = try schedule.aead.seal(
			key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		return (nonce, ct)
	}

	/// Decrypt one segment in random nonce mode; throws on AEAD authentication failure.
	public static func decryptRandom(
		schedule: PayloadSchedule,
		position: SegmentPosition,
		associatedData: [UInt8],
		nonce: [UInt8],
		ciphertext: [UInt8]
	) throws -> [UInt8] {
		let key = schedule.segmentKey(index: position.index)
		let aad = aadRandomMode(
			position: position, associatedData: associatedData, kdf: schedule.kdf)
		return try schedule.aead.open(
			key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
	}

	/// Encrypt one segment in derived nonce mode, returning `ct || tag`. No nonce is
	/// stored; it is recomputed from `nonce_base` and the position.
	public static func encryptDerived(
		schedule: PayloadSchedule,
		position: SegmentPosition,
		associatedData: [UInt8],
		plaintext: [UInt8]
	) throws -> [UInt8] {
		guard let nonceBaseKey = schedule.nonceBase else {
			throw SegmentError.missingNonceBase
		}
		let key = schedule.segmentKey(index: position.index)
		let nonceBase = nonceBaseKey.withUnsafeBytes { Array($0) }
		let nonce = try derivedNonce(nonceBase: nonceBase, position: position)
		let aad = aadDerivedMode(associatedData: associatedData, kdf: schedule.kdf)
		return try schedule.aead.seal(
			key: key, nonce: nonce, aad: aad, plaintext: plaintext)
	}

	/// Decrypt one segment in derived nonce mode; throws on AEAD authentication failure.
	public static func decryptDerived(
		schedule: PayloadSchedule,
		position: SegmentPosition,
		associatedData: [UInt8],
		ciphertext: [UInt8]
	) throws -> [UInt8] {
		guard let nonceBaseKey = schedule.nonceBase else {
			throw SegmentError.missingNonceBase
		}
		let key = schedule.segmentKey(index: position.index)
		let nonceBase = nonceBaseKey.withUnsafeBytes { Array($0) }
		let nonce = try derivedNonce(nonceBase: nonceBase, position: position)
		let aad = aadDerivedMode(associatedData: associatedData, kdf: schedule.kdf)
		return try schedule.aead.open(
			key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
	}

	/// Generate a fresh random `Nn`-octet nonce for random nonce mode.
	public static func freshNonce(for aead: AEAD) -> [UInt8] {
		var nonce = [UInt8](repeating: 0, count: aead.nonceLength)
		for i in nonce.indices {
			nonce[i] = UInt8.random(in: 0...255)
		}
		return nonce
	}
}
