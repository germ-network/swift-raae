import RAAE

/// The public, storable per-object values fixed at `StartEnc` (§3.2): the
/// `payload_info` (which carries the per-object salt) and the commitment. Neither is
/// secret; both are needed to start decryption. The raAE `G` is deliberately absent —
/// it is never stored (§4.6); the decryptor re-supplies it from application context.
public struct SealedObjectHeader: Equatable, Sendable {
	public let payloadInfo: PayloadInfo
	/// `Nh` octets — the engine always uses the default `commitment_length` (§4.2.3).
	public let commitment: [UInt8]

	/// Per-object salt convenience (the salt lives inside `payload_info`).
	public var salt: [UInt8] { payloadInfo.salt }

	public init(payloadInfo: PayloadInfo, commitment: [UInt8]) {
		self.payloadInfo = payloadInfo
		self.commitment = commitment
	}
}

/// One encrypted segment as the engine emits and consumes it. The host owns
/// placement/serialization (§2.1; the §4.11 layouts are informative).
public struct SealedSegment: Equatable, Sendable {
	public let position: SegmentPosition
	/// The stored per-segment nonce: `Nn` octets in random nonce mode, `nil` in
	/// derived mode (`Np = 0`; the nonce is recomputed from the key schedule).
	public let nonce: [UInt8]?
	/// `ct || tag` (§4.8): the AEAD tag is the final `Nt` octets.
	public let ciphertext: [UInt8]

	public init(position: SegmentPosition, nonce: [UInt8]?, ciphertext: [UInt8]) {
		self.position = position
		self.nonce = nonce
		self.ciphertext = ciphertext
	}

	/// The AEAD tag (the final `Nt` octets), the snapshot authenticator's input.
	func tag(length: Int) -> [UInt8] {
		Array(ciphertext.suffix(length))
	}
}

/// The §5.9.5 usage counters: how many encryptions each epoch key and each segment
/// has absorbed. Host-private accounting, not part of the stored object — persist it
/// alongside a `SEAL-RW-v1` object that may be rewritten later, and hand it back to
/// ``SEALConfiguration/resumeWriting(cek:header:snapshot:segments:usageState:globalAssociatedData:)``
/// so the budgets survive the freeze. Losing it means the object must stay frozen
/// (the spec's MUST-track rule): the engine cannot reconstruct how many encryptions
/// a key has already absorbed.
public struct SEALUsageState: Equatable, Sendable {
	/// Encryptions per epoch index (`index >> epoch_length`).
	public var epochCounts: [UInt64: UInt64]
	/// Encryptions per segment index (the §5.9.7.4 hot-rewrite pool in derived mode).
	public var segmentWrites: [UInt64: UInt64]

	public init(
		epochCounts: [UInt64: UInt64] = [:], segmentWrites: [UInt64: UInt64] = [:]
	) {
		self.epochCounts = epochCounts
		self.segmentWrites = segmentWrites
	}
}

/// The result of ``SEALWriter/finalize()``: everything a host stores besides the
/// segments themselves.
public struct SealedObject: Equatable, Sendable {
	public let header: SealedObjectHeader
	/// The published snapshot value (`wrapped_acc || snapshot_tag`, §4.7.4) under
	/// `SEAL-RW-v1`; `nil` under `SEAL-RO-v1` (no snapshot authenticator runs).
	public let snapshot: [UInt8]?
	/// `n_seg` — the number of segments written.
	public let segmentCount: UInt64
	/// The §5.9.5 counters at finalize — persist alongside a rewritable object (see
	/// ``SEALUsageState``); irrelevant for `SEAL-RO-v1`, which never rewrites.
	public let usageState: SEALUsageState
}
