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
	public let aead: AEAD
	public let kdf: KeyDerivation

	/// Truncated KDF output binding CEK + parameters + the global associated data `G`
	/// (§4.6). Length defaults to `Nh`. `G` is bound only here — never stored, supplied
	/// by the decryptor from application context.
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
	/// (§4.5.3.2) — the SEAL product's writer enforces the discipline structurally
	/// for a single live writer.
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
		/// `snap_id` was not a known Table-9 code point (``SnapID``). Unknown values are
		/// rejected like unknown `aead_id`/`kdf_id` — the field is committed into the
		/// KDF, so silently accepting one would bind parameters this build cannot honor.
		case unsupportedSnapID(UInt16)
		/// The `(nonce_mode, snap_id)` tuple is not valid for the named profile
		/// (§4.10.2, Table 13): `SEAL-RW-v1` requires `snap_id 0x0001` (random nonce,
		/// or derived with an MRAE AEAD); `SEAL-RO-v1` pins derived nonce +
		/// `snap_id 0x0000`. An encryptor MUST set a valid tuple and a decryptor MUST
		/// reject an invalid one. Unknown protocol IDs carry their own profile rules
		/// and are not constrained here.
		case invalidProfileTuple(nonceMode: PayloadInfo.NonceMode, snapID: UInt16)
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
	///   MUST obtain the schedule via ``startDecrypt(protocolID:cek:payloadInfo:publishedCommitment:expectedCommitmentLength:globalAssociatedData:)``
	///   (or call ``verifyCommitment(_:)``) before decrypting any segment — the commitment is
	///   SEAL's only key/parameter-committing defense (§4.6), and AES-GCM / ChaCha20-Poly1305
	///   are not key-committing on their own.
	/// - Parameter globalAssociatedData: the raAE `G` (§3.2, §4.6) — whole-message
	///   application context (a name, version, or policy). Committed as one framed
	///   element appended after `payload_info` in the **commitment** derivation only
	///   (the other schedule keys do not bind it); never stored — a decryptor supplies
	///   it from application context, and a wrong `G` fails the commitment check like
	///   a wrong CEK. Defaults to the empty octet string, which is itself committed
	///   (an empty final element), per §4.6.
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
		globalAssociatedData: [UInt8] = [],
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
		// Derived nonce mode fixes each segment's nonce, so a rewrite would reuse it.
		// §4.5.3.2: with a non-MRAE AEAD the mode MUST be confined to a write-once
		// profile. Permit the pairing only under SEAL-RO-v1 (each segment encrypted
		// exactly once); any other protocol ID — including unknown ones — stays strict.
		let isWriteOnce = protocolID == ProtocolID.immutable
		guard !(payloadInfo.nonceMode == .derived && !aead.isMRAE && !isWriteOnce) else {
			throw ScheduleError.derivedModeRequiresMRAE(payloadInfo.aeadID)
		}
		// §4.10.2 Table 13: the named profiles admit only certain (nonce_mode,
		// snap_id) tuples — SEAL-RO-v1 pins derived + snap none (write-once; the
		// finality bit is the truncation signal), SEAL-RW-v1 requires the masked
		// multiset hash so every rewritable object carries whole-object integrity.
		// A decryptor MUST reject an invalid tuple; unknown protocol IDs define
		// their own profile rules and are not constrained here.
		if isWriteOnce {
			guard payloadInfo.nonceMode == .derived, payloadInfo.snapID == SnapID.none
			else {
				throw ScheduleError.invalidProfileTuple(
					nonceMode: payloadInfo.nonceMode, snapID: payloadInfo.snapID
				)
			}
		} else if protocolID == ProtocolID.mutable {
			guard payloadInfo.snapID == SnapID.maskedMultisetHash else {
				throw ScheduleError.invalidProfileTuple(
					nonceMode: payloadInfo.nonceMode, snapID: payloadInfo.snapID
				)
			}
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
		self.aead = aead
		self.kdf = kdf

		let info = payloadInfo.kdfInfoElements
		// commitment is a public authenticator (not secret) → derive(...) -> [UInt8].
		// §4.6: the commitment alone additionally binds the global associated data G
		// as one framed element after payload_info (empty G is still an element).
		self.commitment = kdf.derive(
			protocolID: protocolID, label: Label.commit,
			ikm: [cek], info: info + [globalAssociatedData], outputLength: commitLen)
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
	/// A reader **MUST** call this (or obtain the schedule via ``startDecrypt(protocolID:cek:payloadInfo:publishedCommitment:expectedCommitmentLength:globalAssociatedData:)``)
	/// and abandon decryption on a throw — a mismatch means the wrong CEK or parameters and
	/// MUST be treated as an authentication failure for the object.
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
	/// payload_info)` and verify the published commitment **before** any segment can be
	/// decrypted. This is the recommended safe path — verification is enforced by
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
	/// - Parameter globalAssociatedData: the raAE `G` of the abstract `StartDec`
	///   (§3.2, §4.6) — supplied by the decryptor from application context, never
	///   stored. A wrong `G` re-derives a different commitment and fails as
	///   ``CommitmentError/commitmentMismatch``, exactly like a wrong CEK.
	public static func startDecrypt(
		protocolID: [UInt8],
		cek: [UInt8],
		payloadInfo: PayloadInfo,
		publishedCommitment: [UInt8],
		expectedCommitmentLength: Int? = nil,
		globalAssociatedData: [UInt8] = []
	) throws -> PayloadSchedule {
		if let expected = expectedCommitmentLength, expected != publishedCommitment.count {
			throw CommitmentError.commitmentLengthMismatch(
				expected: expected, got: publishedCommitment.count)
		}
		let schedule = try PayloadSchedule(
			protocolID: protocolID, cek: cek, payloadInfo: payloadInfo,
			globalAssociatedData: globalAssociatedData,
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
