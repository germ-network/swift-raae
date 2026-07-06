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
		/// Derived nonce mode needs `index < 2^63` so `(i<<1)|is_final` fits the
		/// 64-bit value XORed into the nonce (§4.5.3); a larger index would silently
		/// drop its top bit and collide with `index − 2^63`.
		case indexTooLargeForDerivedMode(UInt64)
		/// Derived-mode encryption on a write-once (`SEAL-RO-v1`) schedule with a
		/// non-MRAE AEAD must go through ``PayloadEncryptor``: the §4.5.3.2 discipline
		/// is one encryption per segment, and an unmetered second encryption at the
		/// same position would reuse the segment's fixed nonce — catastrophic for
		/// AES-GCM / ChaCha20-Poly1305 (keystream reuse and forgeability).
		case writeOnceRequiresMeteredEncryptor
		/// The segment plaintext (on decrypt: the plaintext length implied by
		/// `len(ct||tag) − Nt`) exceeded the schedule's `segment_max` (§4.4). Enforced on
		/// both paths: the §5.9.7.4 per-segment budget assumes at most `segment_max`
		/// octets per segment, so an oversized segment would silently weaken the metered
		/// data-volume bound.
		case exceedsSegmentMax(length: Int, segmentMax: UInt32)
	}

	/// Reject a segment longer than the schedule's `segment_max` (§4.4). `length` is the
	/// plaintext length (on decrypt, implied by the ciphertext length minus `Nt`).
	private static func checkSegmentMax(length: Int, schedule: PayloadSchedule) throws {
		guard length <= schedule.payloadInfo.segmentMax else {
			throw SegmentError.exceedsSegmentMax(
				length: length, segmentMax: schedule.payloadInfo.segmentMax)
		}
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
	///
	/// `index` must be below `2^63` so `(i<<1)|is_final` fits the 64-bit XOR block —
	/// Swift's `<<` silently discards the shifted-out top bit, so a larger index would
	/// alias the nonce of `index − 2^63`. (Not exploitable today — indices `2^63` apart
	/// always fall in different epochs for `r ≤ 63`, hence different segment keys — but
	/// the draft's nonce-injectivity assumption should not rest on that.)
	public static func derivedNonce(nonceBase: [UInt8], position: SegmentPosition) throws
		-> [UInt8]
	{
		guard position.index < (UInt64(1) << 63) else {
			throw SegmentError.indexTooLargeForDerivedMode(position.index)
		}
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
		try checkSegmentMax(length: plaintext.count, schedule: schedule)
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
		try checkSegmentMax(
			length: ciphertext.count - schedule.aead.tagLength, schedule: schedule)
		let key = schedule.segmentKey(index: position.index)
		let aad = aadRandomMode(
			position: position, associatedData: associatedData, kdf: schedule.kdf)
		return try schedule.aead.open(
			key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
	}

	/// Encrypt one segment in derived nonce mode, returning `ct || tag`. No nonce is
	/// stored; it is recomputed from `nonce_base` and the position.
	///
	/// On a write-once (`SEAL-RO-v1`) schedule with a non-MRAE AEAD this entry point
	/// refuses to encrypt (``SegmentError/writeOnceRequiresMeteredEncryptor``): §4.5.3.2
	/// licenses that pairing only under a one-encryption-per-segment discipline, which an
	/// unmetered static cannot uphold. Use
	/// ``PayloadEncryptor/encryptDerived(position:associatedData:plaintext:)``, which
	/// meters the discipline and hard-stops rewrites even under ``BudgetPolicy/warn``.
	public static func encryptDerived(
		schedule: PayloadSchedule,
		position: SegmentPosition,
		associatedData: [UInt8],
		plaintext: [UInt8]
	) throws -> [UInt8] {
		guard !(schedule.isWriteOnceProfile && !schedule.aead.isMRAE) else {
			throw SegmentError.writeOnceRequiresMeteredEncryptor
		}
		return try encryptDerivedUnmetered(
			schedule: schedule, position: position, associatedData: associatedData,
			plaintext: plaintext)
	}

	/// The unmetered derived-mode encryption core. Internal: ``PayloadEncryptor`` calls
	/// this after charging the §5.9 budget — the metering is what licenses the
	/// write-once non-MRAE pairing; every external caller goes through
	/// ``encryptDerived(schedule:position:associatedData:plaintext:)``, which gates it.
	static func encryptDerivedUnmetered(
		schedule: PayloadSchedule,
		position: SegmentPosition,
		associatedData: [UInt8],
		plaintext: [UInt8]
	) throws -> [UInt8] {
		try checkSegmentMax(length: plaintext.count, schedule: schedule)
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
		try checkSegmentMax(
			length: ciphertext.count - schedule.aead.tagLength, schedule: schedule)
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
