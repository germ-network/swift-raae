import Crypto
import Foundation

/// The payload schedule (draft §4.5.1–4.5.2): the keys derived deterministically from
/// the CEK and `payload_info`. Holds the resolved suite backends for the message.
///
/// The derived **secret** keys (`payloadKey`, `snapKey`, `nonceBase`, and per-segment
/// keys) are deliberately *not* on the public surface — the draft (§5.8) treats them as
/// never exposed through any public API — and are held as zeroizing `SymmetricKey`
/// values so they are scrubbed when the schedule is released. The `commitment` is a
/// public authenticator, not a secret.
public struct PayloadSchedule {
	public let protocolID: [UInt8]
	public let payloadInfo: PayloadInfo
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

	/// Minimum commitment length (§4.6).
	public static let minCommitmentLength = 16

	/// The draft fixes the CEK at 32 octets (§4.5).
	public static let cekLength = 32

	public enum ScheduleError: Error, Equatable {
		case unsupportedAEAD(UInt16)
		case unsupportedKDF(UInt16)
		case commitmentTooShort(Int)
		/// CEK was not exactly `cekLength` (32) octets.
		case invalidCEKLength(Int)
		/// Derived nonce mode was selected with a non-MRAE AEAD. A rewrite would reuse
		/// the segment's fixed nonce; only an MRAE AEAD (AES-256-GCM-SIV) is safe here.
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
	/// - Parameter commitmentLength: defaults to the KDF's `Nh`; must be ≥ 16.
	public init(
		protocolID: [UInt8],
		cek: [UInt8],
		payloadInfo: PayloadInfo,
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
		// Derived nonce mode reuses a segment's fixed nonce on rewrite, so it is only
		// safe with an MRAE AEAD (draft Table 4). Reject the unsafe pairing up front.
		guard !(payloadInfo.nonceMode == .derived && !aead.isMRAE) else {
			throw ScheduleError.derivedModeRequiresMRAE(payloadInfo.aeadID)
		}
		let commitLen = commitmentLength ?? kdf.outputSize
		guard commitLen >= Self.minCommitmentLength else {
			throw ScheduleError.commitmentTooShort(commitLen)
		}

		self.protocolID = protocolID
		self.payloadInfo = payloadInfo
		self.aead = aead
		self.kdf = kdf

		let info = payloadInfo.kdfInfoElements
		// commitment is a public authenticator (not secret) → derive(...) -> [UInt8].
		self.commitment = kdf.derive(
			protocolID: protocolID, label: Label.commit,
			ikm: [cek], info: info, outputLength: commitLen)
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
	/// A reader **MUST** call this (or obtain the schedule via ``startDecrypt(protocolID:cek:payloadInfo:publishedCommitment:)``)
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
	/// decrypted, so the safe path is the default. Returns the schedule only if the
	/// commitment matches.
	///
	/// The commitment length is taken from `publishedCommitment` (callers must store the
	/// full `commitment_length`-octet value). A short value (< 16 octets) is rejected by
	/// `init` with ``ScheduleError/commitmentTooShort(_:)``.
	///
	/// - Note: the message nonce `N` and global associated data `G` of the abstract
	///   `StartDec` are not yet parameters — SEAL defines no `G`, and there is no header
	///   format yet; §4.6 binds a profile's `G` as an extra framed element after
	///   `payload_info` when one is defined.
	public static func startDecrypt(
		protocolID: [UInt8],
		cek: [UInt8],
		payloadInfo: PayloadInfo,
		publishedCommitment: [UInt8]
	) throws -> PayloadSchedule {
		let schedule = try PayloadSchedule(
			protocolID: protocolID, cek: cek, payloadInfo: payloadInfo,
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
