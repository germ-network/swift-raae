import RAAE

/// Errors raised by the SEAL engine layer (the core's typed errors — `ScheduleError`,
/// `SegmentError`, `AEADError`, `CommitmentError` — propagate unchanged where the
/// engine delegates).
public enum SEALError: Error, Equatable {
	/// Writer used after ``SEALWriter/finalize()``.
	case alreadyFinalized
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
	/// ``SEALConfiguration/resumeWriting(cek:header:snapshot:segments:usageState:globalAssociatedData:)``
	/// on a `SEAL-RO-v1` configuration: "an encryptor MUST NOT rewrite a segment once
	/// it has been written" (§4.10.2).
	case writeOnceProfileForbidsRewrite
	/// `rewrite(_:replacing:)` was handed a segment whose `(index, tag)` is not in
	/// the set the rewriter verified at resume (unknown index, or a stale copy from
	/// before an earlier rewrite of the same index).
	case segmentNotInVerifiedSet(UInt64)
	/// The §5.9.7.4 per-segment (hot-rewrite) budget would be exceeded. Always a
	/// hard stop.
	case segmentBudgetExceeded(index: UInt64, limitLog2: Int)
}

/// Parameter presets from the spec's named-instantiation table (§4.12, Table 15).
/// Each row fixes the profile, `segment_max`, `nonce_mode`, and epoch length; the
/// cipher suite `(aead_id, kdf_id)` stays caller-chosen, e.g.
/// `SEAL-simple(aead_id, kdf_id)`.
///
/// > Important: every spec instantiation also **binds a serialization layout**
/// > (§4.11: linear for attachment/simple, aligned for memory/compact, split for
/// > disk), which this engine does not ship — these presets are the instantiations'
/// > *parameter sets*. A host claiming a named instantiation on the wire must also
/// > implement its bound layout.
public enum SEALScheme: CaseIterable, Equatable, Sendable {
	/// `SEAL-attachment`: write-once content read whole. `SEAL-RO-v1`, 65536,
	/// derived nonce, epoch_length 32.
	case attachment
	/// `SEAL-simple`: the basic mutable object. `SEAL-RW-v1`, 65536, random nonce,
	/// epoch_length 16.
	case simple
	/// `SEAL-memory`: in-memory random access. `SEAL-RW-v1`, 16384, random nonce,
	/// epoch_length 16.
	case memory
	/// `SEAL-disk`: per-segment rewrites on stored media. `SEAL-RW-v1`, 16384,
	/// random nonce, epoch_length 16.
	case disk
	/// `SEAL-compact`: aligned random access with no stored nonce (`Np = 0`).
	/// `SEAL-RW-v1`, 16384, derived nonce, epoch_length 16 — requires an MRAE AEAD
	/// (an in-place rewrite reuses the derived nonce).
	case compact

	var profile: SEALProfile {
		self == .attachment ? .readOnly : .readWrite
	}
	var segmentMax: UInt32 {
		switch self {
		case .attachment, .simple: 65536
		case .memory, .disk, .compact: 16384
		}
	}
	var nonceMode: PayloadInfo.NonceMode {
		switch self {
		case .attachment, .compact: .derived
		case .simple, .memory, .disk: .random
		}
	}
	var epochLength: UInt8 {
		self == .attachment ? 32 : 16
	}

	/// Table 15: "A 256-bit-nonce suite (AEGIS-256, AEGIS-256X2) uses a flat key
	/// (epoch_length 63) regardless of the row." Unreachable today — no 32-octet-
	/// nonce AEAD is registered — but guarded now so registering one later cannot
	/// silently produce spec-divergent presets.
	func epochLength(forNonceLength nonceLength: Int) -> UInt8 {
		nonceLength == 32 ? 63 : epochLength
	}
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
		try self.init(
			profile: profile, aeadID: aeadID, kdfID: kdfID, segmentMax: segmentMax,
			epochLength: epochLength, nonceMode: nil)
	}

	/// A configuration from a §4.12 named-instantiation row (Table 15): the scheme
	/// fixes profile, `segment_max`, `nonce_mode`, and epoch length; the cipher suite
	/// stays caller-chosen. `SEAL-compact` requires an MRAE AEAD (its in-place
	/// rewrite reuses the derived nonce) and throws
	/// `ScheduleError.derivedModeRequiresMRAE` otherwise. A 256-bit-nonce suite
	/// takes a flat key (`epoch_length 63`) regardless of the row, per the table.
	public init(scheme: SEALScheme, aeadID: UInt16, kdfID: UInt16) throws {
		// An unknown aead_id falls through to the designated init's registry check.
		let nonceLength = SuiteRegistry.aead(id: aeadID)?.nonceLength ?? 0
		try self.init(
			profile: scheme.profile, aeadID: aeadID, kdfID: kdfID,
			segmentMax: scheme.segmentMax,
			epochLength: scheme.epochLength(forNonceLength: nonceLength),
			nonceMode: scheme.nonceMode)
	}

	/// Designated initializer. `nonceMode: nil` derives the mode from the profile and
	/// AEAD (RO ⇒ derived; RW ⇒ the AEAD's Table-9 default); an explicit mode (a
	/// Table-15 row) is validated against Table 13 — `SEAL-RW-v1` permits a derived
	/// nonce only with an MRAE AEAD.
	init(
		profile: SEALProfile, aeadID: UInt16, kdfID: UInt16, segmentMax: UInt32,
		epochLength: UInt8, nonceMode: PayloadInfo.NonceMode?
	) throws {
		guard let aead = SuiteRegistry.aead(id: aeadID) else {
			throw PayloadSchedule.ScheduleError.unsupportedAEAD(aeadID)
		}
		guard let kdf = SuiteRegistry.kdf(id: kdfID) else {
			throw PayloadSchedule.ScheduleError.unsupportedKDF(kdfID)
		}
		let mode =
			nonceMode ?? ((profile == .readOnly || aead.isMRAE) ? .derived : .random)
		// Table 13: RO pins derived; RW admits derived only with an MRAE AEAD.
		if profile == .readOnly, mode != .derived {
			throw PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: mode, snapID: SnapID.none)
		}
		if profile == .readWrite, mode == .derived, !aead.isMRAE {
			throw PayloadSchedule.ScheduleError.derivedModeRequiresMRAE(aeadID)
		}
		self.profile = profile
		self.aeadID = aeadID
		self.kdfID = kdfID
		self.segmentMax = segmentMax
		self.epochLength = epochLength
		self.nonceMode = mode
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
