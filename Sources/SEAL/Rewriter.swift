import RAAE

extension SEALConfiguration {
	/// Resume a sealed `SEAL-RW-v1` object for in-place rewriting (raAE `RewriteSeg`,
	/// §3.3 / §4.9.2).
	///
	/// The constructor performs the full read-path verification before anything can
	/// be rewritten: commitment (§4.6, via the same path as
	/// ``startDecryption(cek:header:globalAssociatedData:)``), then `SnapVerify` +
	/// the finality rule over the presented segments — the rewriter only ever
	/// operates on a set it has proven to be the one the writer last recorded. The
	/// raw accumulator is then recovered internally by unmasking the verified
	/// snapshot (`acc = wrapped_acc XOR mask(n_seg, snapshot_tag)`); it never
	/// crosses the API in either direction.
	///
	/// - Parameter segments: the object's complete current segment set (any order).
	/// - Parameter usageState: the §5.9.5 counters persisted when the object was
	///   last frozen (``SealedObject/usageState`` or ``SEALRewriter/usageState``).
	///   Required: budgets MUST survive a freeze, and the engine cannot reconstruct
	///   how many encryptions a key has absorbed.
	/// - Throws: ``SEALError/writeOnceProfileForbidsRewrite`` under `SEAL-RO-v1` —
	///   "an encryptor MUST NOT rewrite a segment once it has been written"
	///   (§4.10.2).
	public func resumeWriting(
		cek: [UInt8], header: SealedObjectHeader, snapshot: [UInt8],
		segments: [SealedSegment], usageState: SEALUsageState,
		globalAssociatedData: [UInt8] = []
	) throws -> SEALRewriter {
		try SEALRewriter(
			configuration: self, cek: cek, header: header, snapshot: snapshot,
			segments: segments, usageState: usageState,
			globalAssociatedData: globalAssociatedData, advantageLog2: 32)
	}

	/// Test seam: a rewriter with a non-default §5.9 collision-advantage target
	/// (larger values shrink the budgets so tests can reach them).
	static func resumeWritingForTesting(
		configuration: SEALConfiguration, cek: [UInt8], header: SealedObjectHeader,
		snapshot: [UInt8], segments: [SealedSegment], usageState: SEALUsageState,
		advantageLog2: Int
	) throws -> SEALRewriter {
		try SEALRewriter(
			configuration: configuration, cek: cek, header: header,
			snapshot: snapshot, segments: segments, usageState: usageState,
			globalAssociatedData: [], advantageLog2: advantageLog2)
	}
}

/// In-place segment replacement over a verified `SEAL-RW-v1` object: each
/// ``rewrite(_:replacing:associatedData:)`` is `RewriteSeg` — a fresh encryption at
/// the same position, the O(1) accumulator update (`remove(i, old_tag)` /
/// `add(i, new_tag)`), and the re-derived snapshot, as one operation (§4.9.2).
/// `n_seg` never changes; extend/truncate are future work.
///
/// A mutable reference type and **not** `Sendable`; serialize external access.
/// Memory: the rewriter holds one tag per segment (`O(n_seg)`).
public final class SEALRewriter {
	public let configuration: SEALConfiguration
	public let header: SealedObjectHeader

	private let schedule: PayloadSchedule
	private let hash: MaskedMultisetHash
	private let budget: UsageBudget
	/// Recovered by unmasking the verified snapshot; never exposed.
	private var accumulator: [UInt8]
	private let segmentCount: UInt64
	/// index → current tag: `rewrite` only replaces a segment it can match here.
	private var currentTags: [UInt64: [UInt8]]
	private var state: SEALUsageState

	/// The §5.9.5 counters including every rewrite so far — persist on freeze and
	/// hand back to the next `resumeWriting`.
	public var usageState: SEALUsageState { state }

	init(
		configuration: SEALConfiguration, cek: [UInt8], header: SealedObjectHeader,
		snapshot: [UInt8], segments: [SealedSegment], usageState: SEALUsageState,
		globalAssociatedData: [UInt8], advantageLog2: Int
	) throws {
		guard configuration.profile == .readWrite else {
			throw SEALError.writeOnceProfileForbidsRewrite
		}
		// Full read-path verification: commitment, then SnapVerify + finality.
		let reader = try configuration.startDecryption(
			cek: cek, header: header, globalAssociatedData: globalAssociatedData)
		try reader.verifySnapshot(snapshot, segments: segments)

		let schedule = reader.schedule
		let hash = MaskedMultisetHash(schedule: schedule)
		let nSeg = UInt64(segments.count)
		// Recover the accumulator from the verified snapshot by unmasking:
		// snapshot = (acc XOR mask(n_seg, tag)) || tag. SnapVerify above proved the
		// snapshot is exactly 2·Nh octets and matches the presented set.
		let wrapped = Array(snapshot.prefix(hash.outputSize))
		let snapshotTag = Array(snapshot.suffix(hash.outputSize))
		let mask = hash.mask(segmentCount: nSeg, snapshotTag: snapshotTag)
		self.accumulator = xor(wrapped, mask)

		self.configuration = configuration
		self.header = header
		self.schedule = schedule
		self.hash = hash
		self.budget = schedule.usageBudget(advantageLog2: advantageLog2)
		self.segmentCount = nSeg
		self.currentTags = Dictionary(
			uniqueKeysWithValues: segments.map {
				($0.position.index, $0.tag(length: schedule.aead.tagLength))
			})
		self.state = usageState
	}

	/// `RewriteSeg(S, p, A_i, M'_i, C_i, snapshot)` (§3.3): replace one segment in
	/// place and return the replacement plus the re-derived snapshot value. The
	/// position (index **and** finality) is preserved from `old`, which must carry
	/// the segment's current tag (a stale copy from before an earlier rewrite is
	/// rejected). In derived mode the fixed nonce is deliberately reused — the
	/// configuration guarantees an MRAE AEAD there, and a rewrite with identical
	/// plaintext and context is deterministic (it leaks only equality).
	public func rewrite(
		_ plaintext: [UInt8], replacing old: SealedSegment,
		associatedData: [UInt8] = []
	) throws -> (segment: SealedSegment, snapshot: [UInt8]) {
		let position = old.position
		let oldTag = old.tag(length: schedule.aead.tagLength)
		guard currentTags[position.index] == oldTag else {
			throw SEALError.segmentNotInVerifiedSet(position.index)
		}
		// §5.9 hard caps: a rewrite is an encryption against both pools.
		let epoch = position.index >> schedule.payloadInfo.epochLength
		let nextEpochCount = (state.epochCounts[epoch] ?? 0) + 1
		if exceedsBudget(nextEpochCount, limitLog2: budget.perEpochKeyLog2) {
			throw SEALError.epochBudgetExceeded(
				epochIndex: epoch, limitLog2: budget.perEpochKeyLog2)
		}
		let nextSegmentCount = (state.segmentWrites[position.index] ?? 0) + 1
		if let perSegment = budget.perSegmentLog2,
			exceedsBudget(nextSegmentCount, limitLog2: perSegment)
		{
			throw SEALError.segmentBudgetExceeded(
				index: position.index, limitLog2: perSegment)
		}

		let replacement: SealedSegment
		switch configuration.nonceMode {
		case .random:
			let (nonce, ct) = try Segment.encryptRandom(
				schedule: schedule, position: position,
				associatedData: associatedData, plaintext: plaintext,
				nonce: Segment.freshNonce(for: schedule.aead))
			replacement = SealedSegment(
				position: position, nonce: nonce, ciphertext: ct)
		case .derived:
			let ct = try Segment.encryptDerivedUnmetered(
				schedule: schedule, position: position,
				associatedData: associatedData, plaintext: plaintext)
			replacement = SealedSegment(position: position, nonce: nil, ciphertext: ct)
		}

		// Commit only after the encryption succeeded: remove(i, old) / add(i, new),
		// then re-derive the published snapshot; n_seg is unchanged.
		let newTag = replacement.tag(length: schedule.aead.tagLength)
		accumulator = hash.rewrittenAccumulator(
			accumulator: accumulator, index: position.index, oldTag: oldTag,
			newTag: newTag)
		currentTags[position.index] = newTag
		state.epochCounts[epoch] = nextEpochCount
		state.segmentWrites[position.index] = nextSegmentCount
		let snapshot = hash.snapshotValue(
			segmentCount: segmentCount, accumulator: accumulator)
		return (replacement, snapshot)
	}
}
