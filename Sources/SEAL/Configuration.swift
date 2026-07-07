import RAAE

/// Errors raised by the SEAL engine layer (the core's typed errors — `ScheduleError`,
/// `SegmentError`, `AEADError`, `CommitmentError` — propagate unchanged where the
/// engine delegates).
public enum SEALError: Error, Equatable {
	/// Writer used after ``SEALWriter/finalize()``.
	case alreadyFinalized
	/// Segment index at or beyond ``SEALLimits/maxSegments`` (the engine cap; the
	/// spec's own derived-mode bound is enforced by the core).
	case segmentIndexExceedsCap(UInt64)
	/// The index was already written. The engine writes each index exactly once —
	/// under `SEAL-RO-v1` that is the normative write-once rule; under `SEAL-RW-v1`
	/// in-place rewrite arrives with the Stage-C rewriter, which also rebinds the
	/// snapshot.
	case duplicateSegmentIndex(UInt64)
	/// A final segment (`is_final = 1`) was already written at `existing`.
	case duplicateFinalSegment(existing: UInt64, new: UInt64)
	/// `finalize()` on a non-empty object whose highest index is not the (unique)
	/// final segment (§4.11.1: the last segment carries `is_final = 1`).
	case malformedFinality(finalIndex: UInt64?, maxIndex: UInt64)
	/// The §5.9 per-epoch-key encryption budget would be exceeded. Always a hard
	/// stop: the engine has no warn mode.
	case epochBudgetExceeded(epochIndex: UInt64, limitLog2: Int)
	/// The header's `payload_info` disagrees with this configuration (everything but
	/// the per-object salt must match).
	case headerMismatch
	/// ``SEALReader/verifySnapshot(_:segments:)`` on a profile without a snapshot
	/// authenticator (`SEAL-RO-v1` pins `snap_id 0x0000`).
	case noSnapshotAuthenticator
	/// SnapVerify failed: the presented segment set is not the one the writer last
	/// recorded (added/dropped/modified segment, or a count change).
	case snapshotMismatch
	/// The presented set's positions are structurally malformed: a duplicate index,
	/// no final segment, more than one, or a final segment that is not the highest
	/// index (§4.9.1.2 finality rule).
	case incompleteSegmentSet
	/// A segment's stored-nonce metadata is inconsistent with the configuration's
	/// nonce mode (`Np = Nn` in random mode, `Np = 0` in derived mode).
	case nonceMetadataMismatch
}

/// A SEAL suite + profile, validated at construction (§4.10.2): the engine's opaque
/// parameter object. `nonce_mode` and `snap_id` are **not** caller choices — the
/// profile and AEAD determine them (Table 13, Table 9 defaults) — so invalid tuples
/// and mode mixing are unrepresentable at this layer (the core additionally enforces
/// the tuple MUST as defense-in-depth).
public struct SEALConfiguration: Sendable {
	public let profile: SEALProfile
	public let aeadID: UInt16
	public let kdfID: UInt16
	/// Maximum segment size in octets; a validated power of two ≥ 4096 (§4.4).
	public let segmentMax: UInt32
	/// `r ∈ [0, 63]`; each epoch key covers `2^r` consecutive segment indices.
	public let epochLength: UInt8
	/// Derived, not chosen: `SEAL-RO-v1` ⇒ derived; `SEAL-RW-v1` ⇒ the AEAD's
	/// Table-9 default (derived for the MRAE suite, random otherwise).
	public let nonceMode: PayloadInfo.NonceMode
	/// Derived, not chosen (Table 13): `SEAL-RW-v1` ⇒ masked multiset hash,
	/// `SEAL-RO-v1` ⇒ none.
	public var snapID: UInt16 {
		profile == .readOnly ? SnapID.none : SnapID.maskedMultisetHash
	}

	/// The resolved suite backends, validated at init.
	let aead: AEAD
	let kdf: KeyDerivation

	/// Validates the suite and geometry eagerly; throws the core's typed errors
	/// (`PayloadInfo.ValidationError`, `PayloadSchedule.ScheduleError`).
	public init(
		profile: SEALProfile,
		aeadID: UInt16,
		kdfID: UInt16,
		segmentMax: UInt32 = 65536,
		epochLength: UInt8 = 0
	) throws {
		guard let aead = SuiteRegistry.aead(id: aeadID) else {
			throw PayloadSchedule.ScheduleError.unsupportedAEAD(aeadID)
		}
		guard let kdf = SuiteRegistry.kdf(id: kdfID) else {
			throw PayloadSchedule.ScheduleError.unsupportedKDF(kdfID)
		}
		self.profile = profile
		self.aeadID = aeadID
		self.kdfID = kdfID
		self.segmentMax = segmentMax
		self.epochLength = epochLength
		self.nonceMode = (profile == .readOnly || aead.isMRAE) ? .derived : .random
		self.aead = aead
		self.kdf = kdf
		// Validate the geometry through the core's own checks (salt is per-object;
		// use a placeholder of the correct length for the template validation).
		try payloadInfo(salt: [UInt8](repeating: 0, count: 32)).validate()
	}

	/// The `payload_info` this configuration produces for a given per-object salt.
	/// Public so a host that persists only `(salt, commitment)` can reconstruct the
	/// ``SealedObjectHeader``.
	public func payloadInfo(salt: [UInt8]) -> PayloadInfo {
		PayloadInfo(
			aeadID: aeadID, segmentMax: segmentMax, kdfID: kdfID, snapID: snapID,
			nonceMode: nonceMode, epochLength: epochLength, salt: salt)
	}

	/// Generate a fresh 32-octet CEK (§4.5) from the system CSPRNG.
	///
	/// - Note: returned as a caller-owned `[UInt8]` to match the core's CEK
	///   parameters; Swift arrays are not zeroizing — a host holding CEKs long-term
	///   should manage them in its own secure storage.
	public static func generateCEK() -> [UInt8] {
		randomBytes(PayloadSchedule.cekLength)
	}
}

/// Fresh bytes from the system CSPRNG (`SystemRandomNumberGenerator`:
/// `arc4random_buf` / `getrandom`).
func randomBytes(_ count: Int) -> [UInt8] {
	var rng = SystemRandomNumberGenerator()
	var out = [UInt8](repeating: 0, count: count)
	for i in out.indices {
		out[i] = UInt8.random(in: .min ... .max, using: &rng)
	}
	return out
}
