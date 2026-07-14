import Crypto
import Foundation

/// The payload schedule (draft §4.5.1–4.5.2): the keys derived deterministically from
/// the CEK and `payload_info`. Holds the resolved suite backends for the message.
///
/// The derived **secret** keys (`payloadKey`, `snapKey`, `nonceBase`, and per-segment
/// keys) are deliberately *not* on the public surface — the draft (§5.8) treats them as
/// never exposed through any public API — and are held as zeroizing `SymmetricKey`
/// values so they are scrubbed when the *last reference* to the key is released (so on a
/// `startDecrypt` mismatch, dropping the rejected schedule satisfies the §4.6 SHOULD to
/// zeroize derived key material — callers must not retain it). The `commitment` is a
/// public authenticator, not a secret.
public struct PayloadSchedule {
	public let protocolID: [UInt8]
	public let payloadInfo: PayloadInfo
	/// Global associated data `G` (§4.2.4), bound into the ``commitment`` and nothing
	/// else — the other three derivations never take it (§4.5.1). It carries
	/// whole-message application context (for MLS attachments, the `object_id`) that is
	/// never stored with the object (§4.6): a decryptor re-supplies it, and a wrong or
	/// missing `G` fails ``verifyCommitment(_:)`` exactly like a wrong CEK. `G` is
	/// framed like any KDF field, so any length is accepted (over-large values hash
	/// through `LH`).
	///
	/// - Note: `G` is **always** framed as the last element of the commitment info,
	///   including the empty default (a zero-length element), per
	///   draft-sullivan-cfrg-raae-02 ("always the last element of the commitment info
	///   … so every commitment derivation includes it"). The vendored Appendix F corpus
	///   carries the commitment values this produces (`Spec/SOURCE.md`); the empty-G
	///   pin is `GlobalAADTests`, and non-empty `G` is pinned against Appendix F.2 there.
	public let globalAAD: [UInt8]
	public let aead: AEAD
	public let kdf: KeyDerivation

	/// Truncated KDF output binding CEK + parameters (§4.6). Length defaults to `Nh`.
	public let commitment: [UInt8]
	/// Root key for per-segment (epoch) key derivation. Internal; never vended raw (§5.8).
	let payloadKey: SymmetricKey
	/// Snapshot authenticator key (`acc_key`). Internal; never vended raw (§5.8).
	let snapKey: SymmetricKey
	/// Base nonce for derived mode; `nil` in random mode. Internal (§5.8).
	let nonceBase: SymmetricKey?

	/// Whether this schedule's protocol ID selects the write-once profile
	/// (`SEAL-RO-v1`, §4.10.2): every segment is encrypted exactly once and never
	/// rewritten. This is what licenses derived nonce mode with a non-MRAE AEAD
	/// (§4.5.3.2) — the discipline itself is the caller's obligation (and is metered
	/// by `PayloadEncryptor` for a single live writer).
	public var isWriteOnceProfile: Bool { protocolID == ProtocolID.immutable }

	/// Minimum commitment length (§4.6). At this 16-octet draft floor the
	/// key-committing property has only ~2^64 collision resistance — a multi-key
	/// adversary searching for two CEKs sharing one commitment works at the birthday
	/// bound of the truncated output. Keep the default full-`Nh` commitment unless an
	/// interop profile demands the floor.
	public static let minCommitmentLength = 16

	/// Largest commitment length a given KDF can safely produce: bounded by HKDF's `255·Nh`
	/// output limit and the uint16 framing of the output length. A commitment never needs to
	/// exceed `Nh`; this ceiling exists only to reject over-long values with a typed error
	/// rather than trapping in the KDF.
	static func maxCommitmentLength(for kdf: KeyDerivation) -> Int {
		min(255 * kdf.outputSize, Framing.maxLiteralLength)
	}

	/// The draft fixes the CEK at 32 octets (§4.5).
	public static let cekLength = 32

	public enum ScheduleError: Error, Equatable {
		case unsupportedAEAD(UInt16)
		case unsupportedKDF(UInt16)
		/// `snap_id` was not a known Table-12 code point (``SnapID``). Unknown values are
		/// rejected like unknown `aead_id`/`kdf_id` — the field is committed into the
		/// KDF, so silently accepting one would bind parameters this build cannot honor.
		case unsupportedSnapID(UInt16)
		case commitmentTooShort(Int)
		/// Commitment length exceeded what the KDF can emit / the framing can encode
		/// (`min(255·Nh, 0xFFFE)`). Rejected up front so an over-long (e.g. attacker-supplied)
		/// `publishedCommitment` cannot trap in `Bytes.uint16` / HKDF `expand` before the
		/// §4.6 verification runs.
		case commitmentTooLong(Int)
		/// CEK was not exactly `cekLength` (32) octets.
		case invalidCEKLength(Int)
		/// Derived nonce mode was selected with a non-MRAE AEAD under a rewritable
		/// profile. A rewrite would reuse the segment's fixed nonce; only an MRAE AEAD
		/// (AES-256-GCM-SIV) is safe there (§4.5.3.2). The pairing is permitted under
		/// the write-once `SEAL-RO-v1` profile (``ProtocolID/immutable``), where each
		/// derived nonce is used exactly once; unknown protocol IDs are treated as
		/// rewritable (strict).
		case derivedModeRequiresMRAE(UInt16)
		/// The `(nonce_mode, snap_id)` tuple is not valid for the named profile
		/// (§4.10.2 Table 14): `SEAL-RW-v1` requires a snapshot authenticator
		/// (`snap_id != 0x0000`), and `SEAL-RO-v1` requires a derived nonce with
		/// `snap_id = 0x0000` (of this build's supported authenticators). An encryptor
		/// MUST NOT emit such a tuple and a decryptor MUST reject it — the decrypt-side
		/// MUST flows through ``startDecrypt(protocolID:cek:payloadInfo:globalAAD:publishedCommitment:expectedCommitmentLength:)``,
		/// which uses this same initializer. Unknown protocol IDs carry no tuple
		/// constraint (a custom profile defines its own; only the §4.5.3.2 MRAE gate
		/// applies).
		case invalidProfileTuple(nonceMode: UInt8, snapID: UInt16)
	}

	/// Failures of the §4.6 commitment check. Kept distinct from ``ScheduleError``
	/// (derivation) and ``AEADError`` (segment open) so the three failure modes of §4.9.1.2
	/// — wrong key/params, tampered segment, modified set — map to three Swift error types.
	public enum CommitmentError: Error, Equatable {
		/// The published commitment did not match the one derived from this (CEK, params).
		/// Per §4.6 the reader MUST treat this as an authentication failure and not decrypt.
		case commitmentMismatch
		/// The published commitment's length differs from this schedule's commitment length.
		case commitmentLengthMismatch(expected: Int, got: Int)
	}

	/// Derive the schedule from a 32-octet CEK and the message's `payload_info`.
	///
	/// - Important: this initializer does **not** verify a commitment. A decrypt-side caller
	///   MUST obtain the schedule via ``startDecrypt(protocolID:cek:payloadInfo:globalAAD:publishedCommitment:expectedCommitmentLength:)``
	///   (or call ``verifyCommitment(_:)``) before decrypting any segment — the commitment is
	///   SEAL's only key/parameter-committing defense (§4.6), and AES-GCM / ChaCha20-Poly1305
	///   are not key-committing on their own.
	/// - Parameter globalAAD: the global associated data `G` (§4.2.4), bound into the
	///   commitment as an extra framed element after `payload_info` (§4.5.1) — see
	///   ``globalAAD``. Defaults to empty, which is still framed (as a zero-length
	///   element) per the draft; a wrong or missing `G` fails as `commitmentMismatch`.
	/// - Parameter commitmentLength: defaults to the KDF's `Nh`; must be in
	///   `[16, min(255·Nh, 0xFFFE)]`. Out-of-range values throw
	///   ``ScheduleError/commitmentTooShort(_:)`` / ``ScheduleError/commitmentTooLong(_:)``.
	///   Keep the default: truncation halves the committing property's bits (the
	///   16-octet floor leaves ~2^64 collision resistance against multi-key
	///   adversaries; see ``minCommitmentLength``).
	public init(
		protocolID: [UInt8],
		cek: [UInt8],
		payloadInfo: PayloadInfo,
		globalAAD: [UInt8] = [],
		commitmentLength: Int? = nil
	) throws {
		try payloadInfo.validate()
		guard cek.count == Self.cekLength else {
			throw ScheduleError.invalidCEKLength(cek.count)
		}
		guard let aead = SuiteRegistry.aead(id: payloadInfo.aeadID) else {
			throw ScheduleError.unsupportedAEAD(payloadInfo.aeadID)
		}
		guard let kdf = SuiteRegistry.kdf(id: payloadInfo.kdfID) else {
			throw ScheduleError.unsupportedKDF(payloadInfo.kdfID)
		}
		guard SuiteRegistry.isKnownSnapID(payloadInfo.snapID) else {
			throw ScheduleError.unsupportedSnapID(payloadInfo.snapID)
		}
		// §4.10.2 Table 14: only certain (nonce_mode, snap_id) tuples are valid under
		// each named profile, and a decryptor MUST reject any object off that table.
		// Of this build's authenticators: SEAL-RW-v1 requires the masked multiset hash
		// (every rewritable object carries whole-object integrity), and SEAL-RO-v1
		// requires a derived nonce with no snapshot authenticator. Unknown protocol IDs
		// define their own tuples and pass (only the §4.5.3.2 MRAE gate below applies).
		let isWriteOnce = protocolID == ProtocolID.immutable
		let offProfile =
			(protocolID == ProtocolID.mutable && payloadInfo.snapID == SnapID.none)
			|| (isWriteOnce
				&& (payloadInfo.nonceMode != .derived
					|| payloadInfo.snapID != SnapID.none))
		guard !offProfile else {
			throw ScheduleError.invalidProfileTuple(
				nonceMode: payloadInfo.nonceMode.rawValue,
				snapID: payloadInfo.snapID)
		}
		// Derived nonce mode fixes each segment's nonce, so a rewrite would reuse it.
		// §4.5.3.2: with a non-MRAE AEAD the mode MUST be confined to a write-once
		// profile. Permit the pairing only under SEAL-RO-v1 (each segment encrypted
		// exactly once); any other protocol ID — including unknown ones — stays strict.
		guard !(payloadInfo.nonceMode == .derived && !aead.isMRAE && !isWriteOnce) else {
			throw ScheduleError.derivedModeRequiresMRAE(payloadInfo.aeadID)
		}
		let commitLen = commitmentLength ?? kdf.outputSize
		guard commitLen >= Self.minCommitmentLength else {
			throw ScheduleError.commitmentTooShort(commitLen)
		}
		// Upper-bound the commitment length. HKDF `expand` emits at most 255·Nh octets and
		// framing encodes the output length as a uint16, so a larger value would trap in
		// `Bytes.uint16` (> 0xFFFF) or the HKDF iteration count (> 255·Nh) *before* the §4.6
		// verification runs — a reachable panic on the verify-before-decrypt path, since
		// `startDecrypt` derives `commitmentLength` from the (untrusted) published commitment.
		// A commitment beyond Nh has no security benefit (it truncates one KDF block), so
		// reject it with a typed error instead of aborting the process.
		guard commitLen <= Self.maxCommitmentLength(for: kdf) else {
			throw ScheduleError.commitmentTooLong(commitLen)
		}

		self.protocolID = protocolID
		self.payloadInfo = payloadInfo
		self.globalAAD = globalAAD
		self.aead = aead
		self.kdf = kdf

		let info = payloadInfo.kdfInfoElements
		// §4.5.1: G binds into the commitment only, as an extra framed element after
		// payload_info — payload_key / acc_key / nonce_base never take it. G is always
		// framed as the last commitment element (a zero-length element when empty):
		// "always the last element of the commitment info … so every commitment
		// derivation includes it".
		let commitInfo = info + [globalAAD]
		// commitment is a public authenticator (not secret) → derive(...) -> [UInt8].
		self.commitment = kdf.derive(
			protocolID: protocolID, label: Label.commit,
			ikm: [cek], info: commitInfo, outputLength: commitLen)
		// Secret outputs → deriveKey(...) -> SymmetricKey (zeroizing).
		self.payloadKey = kdf.deriveKey(
			protocolID: protocolID, label: Label.payloadKey,
			ikm: [cek], info: info, outputLength: aead.keyLength)
		self.snapKey = kdf.deriveKey(
			protocolID: protocolID, label: Label.accKey,
			ikm: [cek], info: info, outputLength: kdf.outputSize)
		self.nonceBase =
			payloadInfo.nonceMode == .derived
			? kdf.deriveKey(
				protocolID: protocolID, label: Label.nonceBase,
				ikm: [cek], info: info, outputLength: aead.nonceLength)
			: nil
	}

	/// Verify a published commitment against this schedule's, in constant time (§4.6).
	///
	/// A reader **MUST** call this (or obtain the schedule via ``startDecrypt(protocolID:cek:payloadInfo:globalAAD:publishedCommitment:expectedCommitmentLength:)``)
	/// and abandon decryption on a throw — a mismatch means the wrong CEK, parameters, or
	/// global associated data `G`, and MUST be treated as an authentication failure for
	/// the object.
	public func verifyCommitment(_ published: [UInt8]) throws {
		guard published.count == commitment.count else {
			throw CommitmentError.commitmentLengthMismatch(
				expected: commitment.count, got: published.count)
		}
		guard ConstantTime.equals(published, commitment) else {
			throw CommitmentError.commitmentMismatch
		}
	}

	/// raAE `StartDec` (§3.2 / §4.1 Table 1): re-derive the schedule from `(CEK,
	/// payload_info, G)` and verify the published commitment **before** any segment can
	/// be decrypted. This is the recommended safe path — verification is enforced by
	/// convention (a documented MUST), not by the type system, since the public `init` can
	/// still build an unverified schedule. Returns the schedule only if the commitment
	/// matches.
	///
	/// The commitment length is taken from `publishedCommitment` (callers must store the
	/// full `commitment_length`-octet value). A short value (< 16 octets) is rejected by
	/// `init` with ``ScheduleError/commitmentTooShort(_:)``, and an over-long one (beyond the
	/// KDF's `255·Nh` / framing limit) with ``ScheduleError/commitmentTooLong(_:)`` — so a
	/// malformed published commitment fails as a typed error, never a process abort in the
	/// KDF. Truncation cannot silently
	/// downgrade the binding: the output length is bound into the KDF, so a truncated
	/// commitment re-derives to a different value and fails as `commitmentMismatch`. A caller
	/// who knows the authored `commitment_length` out of band may pass
	/// `expectedCommitmentLength` to get a precise
	/// ``CommitmentError/commitmentLengthMismatch(expected:got:)`` instead.
	///
	/// - Note: `globalAAD` is the abstract `StartDec`'s global associated data `G`
	///   (§3.2); the per-message nonce role is played by the salt inside `payload_info`.
	///   `G` is never stored with the object (§4.6) — the caller supplies it from
	///   application context (for MLS attachments, the `object_id`), and a wrong or
	///   missing value fails as ``CommitmentError/commitmentMismatch``, exactly like a
	///   wrong CEK.
	public static func startDecrypt(
		protocolID: [UInt8],
		cek: [UInt8],
		payloadInfo: PayloadInfo,
		globalAAD: [UInt8] = [],
		publishedCommitment: [UInt8],
		expectedCommitmentLength: Int? = nil
	) throws -> PayloadSchedule {
		if let expected = expectedCommitmentLength, expected != publishedCommitment.count {
			throw CommitmentError.commitmentLengthMismatch(
				expected: expected, got: publishedCommitment.count)
		}
		let schedule = try PayloadSchedule(
			protocolID: protocolID, cek: cek, payloadInfo: payloadInfo,
			globalAAD: globalAAD,
			commitmentLength: publishedCommitment.count)
		try schedule.verifyCommitment(publishedCommitment)
		return schedule
	}

	/// `segment_key(i) = KDF(protocol_id, "epoch_key", [payload_key], [uint64(i >> r)], Nk)` (§4.5.2).
	/// Returns a zeroizing `SymmetricKey`; internal, never vended raw (§5.8).
	func segmentKey(index: UInt64) -> SymmetricKey {
		let epochIndex = index >> payloadInfo.epochLength
		// payload_key is the (secret) ikm; the framing transiently materializes it.
		let payloadKeyBytes = payloadKey.withUnsafeBytes { Array($0) }
		return kdf.deriveKey(
			protocolID: protocolID, label: Label.epochKey,
			ikm: [payloadKeyBytes], info: [Bytes.uint64(epochIndex)],
			outputLength: aead.keyLength)
	}
}
