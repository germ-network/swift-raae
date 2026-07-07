import RAAE

extension SEALConfiguration {
	/// raAE `StartEnc(K, N, G)` (§3.2): begin authoring one object.
	///
	/// The 32-octet per-object salt is generated internally from the system CSPRNG —
	/// salt uniqueness is what keeps two objects under one CEK from sharing a key
	/// schedule — and the returned writer owns every other sharp edge: nonce
	/// generation, the §5.9 budget (hard caps), snapshot maintenance, and the
	/// write-each-index-once discipline.
	///
	/// - Parameter globalAssociatedData: the raAE `G` (§4.6) — whole-message
	///   application context, bound into the commitment, never stored; the decryptor
	///   re-supplies it.
	public func startEncryption(
		cek: [UInt8], globalAssociatedData: [UInt8] = []
	) throws -> SEALWriter {
		try SEALWriter(
			configuration: self, cek: cek, globalAssociatedData: globalAssociatedData,
			advantageLog2: 32)
	}

	/// Test seam: a writer with a non-default §5.9 collision-advantage target
	/// (larger values shrink the budgets so tests can reach them). The public path
	/// always uses the draft's `2^-32`.
	static func startEncryptionForTesting(
		configuration: SEALConfiguration, cek: [UInt8], advantageLog2: Int
	) throws -> SEALWriter {
		try SEALWriter(
			configuration: configuration, cek: cek, globalAssociatedData: [],
			advantageLog2: advantageLog2)
	}
}

/// The authoring half of the engine: `EncSeg` over an immutable schedule with the
/// discipline the spec assigns to writers built in — each index written exactly once
/// (rewrite is the Stage-C rewriter's job, snapshot rebind included), one final
/// segment which must be the highest index (§4.11.1), hard §5.9 budget caps, and
/// internal snapshot accounting (the raw accumulator never leaves the writer).
///
/// A mutable reference type and **not** `Sendable`; serialize external access.
/// Accounting is per-instance and in-memory — authoring an object across processes
/// (freeze/resume) arrives with the Stage-C rewriter.
public final class SEALWriter {
	public let configuration: SEALConfiguration
	/// Available immediately: salt and commitment are fixed at `StartEnc`.
	public let header: SealedObjectHeader

	private let schedule: PayloadSchedule
	private let budget: UsageBudget
	private let snapshotHash: MaskedMultisetHash?
	private var accumulator: [UInt8]
	private var epochCounts: [UInt64: UInt64] = [:]
	private var written: Set<UInt64> = []
	private var maxIndex: UInt64?
	private var finalIndex: UInt64?
	private var finalized = false

	init(
		configuration: SEALConfiguration, cek: [UInt8], globalAssociatedData: [UInt8],
		advantageLog2: Int
	) throws {
		let info = configuration.payloadInfo(salt: randomBytes(32))
		let schedule = try PayloadSchedule(
			protocolID: configuration.profile.protocolID, cek: cek,
			payloadInfo: info, globalAssociatedData: globalAssociatedData)
		self.configuration = configuration
		self.schedule = schedule
		self.header = SealedObjectHeader(
			payloadInfo: info, commitment: schedule.commitment)
		self.budget = schedule.usageBudget(advantageLog2: advantageLog2)
		if configuration.snapID == SnapID.maskedMultisetHash {
			let hash = MaskedMultisetHash(schedule: schedule)
			self.snapshotHash = hash
			self.accumulator = [UInt8](repeating: 0, count: hash.outputSize)
		} else {
			self.snapshotHash = nil
			self.accumulator = []
		}
	}

	/// raAE `EncSeg` (§3.2) with the engine's discipline. Returns the segment for
	/// the host to place; in random nonce mode the freshly generated nonce rides in
	/// ``SealedSegment/nonce`` and must be stored, in derived mode it is `nil`.
	public func encrypt(
		_ plaintext: [UInt8], at position: SegmentPosition,
		associatedData: [UInt8] = []
	) throws -> SealedSegment {
		guard !finalized else { throw SEALError.alreadyFinalized }
		guard position.index < SEALLimits.maxSegments else {
			throw SEALError.segmentIndexExceedsCap(position.index)
		}
		guard !written.contains(position.index) else {
			throw SEALError.duplicateSegmentIndex(position.index)
		}
		if position.isFinal, let existing = finalIndex {
			throw SEALError.duplicateFinalSegment(
				existing: existing, new: position.index)
		}
		// §5.9: hard per-epoch-key cap. Per-segment caps are structural here — each
		// index is written exactly once.
		let epoch = position.index >> schedule.payloadInfo.epochLength
		let nextCount = (epochCounts[epoch] ?? 0) + 1
		if exceedsBudget(nextCount, limitLog2: budget.perEpochKeyLog2) {
			throw SEALError.epochBudgetExceeded(
				epochIndex: epoch, limitLog2: budget.perEpochKeyLog2)
		}

		let segment: SealedSegment
		switch configuration.nonceMode {
		case .random:
			let (nonce, ct) = try Segment.encryptRandom(
				schedule: schedule, position: position,
				associatedData: associatedData, plaintext: plaintext,
				nonce: Segment.freshNonce(for: schedule.aead))
			segment = SealedSegment(position: position, nonce: nonce, ciphertext: ct)
		case .derived:
			// The unmetered core seam: this writer *is* the meter (the
			// write-each-index-once set above), which is what licenses the
			// write-once non-MRAE pairing (§4.5.3.2).
			let ct = try Segment.encryptDerivedUnmetered(
				schedule: schedule, position: position,
				associatedData: associatedData, plaintext: plaintext)
			segment = SealedSegment(position: position, nonce: nil, ciphertext: ct)
		}

		// Commit state only after the encryption succeeded.
		epochCounts[epoch] = nextCount
		written.insert(position.index)
		maxIndex = max(maxIndex ?? position.index, position.index)
		if position.isFinal { finalIndex = position.index }
		if let hash = snapshotHash {
			accumulator = xor(
				accumulator,
				hash.contribution(
					index: position.index,
					tag: segment.tag(length: schedule.aead.tagLength)))
		}
		return segment
	}

	/// Complete the object: enforce the §4.11.1 finality shape (a non-empty object's
	/// unique final segment is its highest index; an empty object has none) and, under
	/// `SEAL-RW-v1`, publish the snapshot over the recorded set. The writer is
	/// single-use; further calls throw.
	public func finalize() throws -> SealedObject {
		guard !finalized else { throw SEALError.alreadyFinalized }
		if let maxIndex {
			guard finalIndex == maxIndex else {
				throw SEALError.malformedFinality(
					finalIndex: finalIndex, maxIndex: maxIndex)
			}
		}
		finalized = true
		let snapshot = snapshotHash.map {
			$0.snapshotValue(
				segmentCount: UInt64(written.count), accumulator: accumulator)
		}
		return SealedObject(
			header: header, snapshot: snapshot, segmentCount: UInt64(written.count))
	}
}

/// `count > 2^limitLog2`, guarding the shift edges (≥ 64 ⇒ unbounded).
func exceedsBudget(_ count: UInt64, limitLog2: Int) -> Bool {
	if limitLog2 >= 64 { return false }
	if limitLog2 < 0 { return true }
	return count > (UInt64(1) << UInt64(limitLog2))
}

func xor(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
	precondition(lhs.count == rhs.count)
	var out = lhs
	for i in out.indices { out[i] ^= rhs[i] }
	return out
}
