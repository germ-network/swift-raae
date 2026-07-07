import RAAE

extension SEALConfiguration {
	/// raAE `StartDec(K, N, G, T_g)` (§3.2): the **only** way to obtain a reader,
	/// and it verifies the commitment (§4.6) before returning — wrong CEK, wrong
	/// parameters, wrong `G`, or a corrupted header all fail here as
	/// `CommitmentError`, before any segment can be decrypted.
	///
	/// The header's `payload_info` must match this configuration in every field but
	/// the per-object salt (``SEALError/headerMismatch``): the reader's expected
	/// parameters come from application context, not from the (attacker-writable)
	/// stored object, and the engine pins `commitment_length = Nh`.
	public func startDecryption(
		cek: [UInt8], header: SealedObjectHeader, globalAssociatedData: [UInt8] = []
	) throws -> SEALReader {
		let info = header.payloadInfo
		guard payloadInfo(salt: info.salt) == info else {
			throw SEALError.headerMismatch
		}
		let schedule = try PayloadSchedule.startDecrypt(
			protocolID: profile.protocolID, cek: cek, payloadInfo: info,
			publishedCommitment: header.commitment,
			expectedCommitmentLength: kdf.outputSize,
			globalAssociatedData: globalAssociatedData)
		return SEALReader(configuration: self, schedule: schedule)
	}
}

/// The reading half of the engine, per the §4.9.1.2 read path: the constructor
/// (``SEALConfiguration/startDecryption(cek:header:globalAssociatedData:)``) has
/// already verified the commitment; ``decrypt(_:associatedData:)`` opens individual
/// segments in any order; ``verifySnapshot(_:segments:)`` checks whole-object
/// integrity under `SEAL-RW-v1`; ``verifyFinality(positions:)`` checks the
/// truncation-defense shape of a presented set (the sole whole-object signal under
/// `SEAL-RO-v1`).
public struct SEALReader {
	public let configuration: SEALConfiguration
	let schedule: PayloadSchedule

	init(configuration: SEALConfiguration, schedule: PayloadSchedule) {
		self.configuration = configuration
		self.schedule = schedule
	}

	/// raAE `DecSeg` (§3.2); throws `AEADError.authenticationFailure` on any
	/// tampering. Position and finality are authenticated (through the AAD in random
	/// mode, the nonce in derived mode), so a segment presented at the wrong
	/// position fails.
	public func decrypt(
		_ segment: SealedSegment, associatedData: [UInt8] = []
	) throws -> [UInt8] {
		guard segment.position.index < SEALLimits.maxSegments else {
			throw SEALError.segmentIndexExceedsCap(segment.position.index)
		}
		switch configuration.nonceMode {
		case .random:
			guard let nonce = segment.nonce else {
				throw SEALError.nonceMetadataMismatch
			}
			return try Segment.decryptRandom(
				schedule: schedule, position: segment.position,
				associatedData: associatedData, nonce: nonce,
				ciphertext: segment.ciphertext)
		case .derived:
			guard segment.nonce == nil else {
				throw SEALError.nonceMetadataMismatch
			}
			return try Segment.decryptDerived(
				schedule: schedule, position: segment.position,
				associatedData: associatedData, ciphertext: segment.ciphertext)
		}
	}

	/// `SnapVerify` (§4.9.1.2) plus the structural finality check: the presented
	/// segments must be exactly the set the writer last recorded (constant-time
	/// comparison; add/drop/modify and count changes are rejected) and must satisfy
	/// ``verifyFinality(positions:)``. Only meaningful under `SEAL-RW-v1`; throws
	/// ``SEALError/noSnapshotAuthenticator`` under `SEAL-RO-v1`.
	///
	/// - Note: this proves set integrity, not recency — a complete old
	///   `(segments, snapshot)` pair replays. Freshness is the host's obligation.
	public func verifySnapshot(
		_ snapshot: [UInt8], segments: [SealedSegment]
	) throws {
		guard let hash = snapshotAuthenticator else {
			throw SEALError.noSnapshotAuthenticator
		}
		try verifyFinality(positions: segments.map(\.position))
		let tagged = segments.map {
			(index: $0.position.index, tag: $0.tag(length: schedule.aead.tagLength))
		}
		guard hash.verify(snapshot: snapshot, segments: tagged) else {
			throw SEALError.snapshotMismatch
		}
	}

	/// The §4.9.1.2 finality rule over a presented set's *claimed* positions: no
	/// duplicate indices, and a non-empty set has exactly one final segment, at the
	/// highest index. Under `SEAL-RO-v1` this is the sole truncation defense
	/// (§4.10.2), and each claim is confirmed cryptographically when its segment is
	/// decrypted — whole-object completeness therefore requires decrypting the final
	/// segment.
	public func verifyFinality(positions: [SegmentPosition]) throws {
		guard !positions.isEmpty else { return }
		var seen = Set<UInt64>()
		var finals: [UInt64] = []
		var maxIndex: UInt64 = 0
		for position in positions {
			guard seen.insert(position.index).inserted else {
				throw SEALError.incompleteSegmentSet
			}
			if position.isFinal { finals.append(position.index) }
			maxIndex = max(maxIndex, position.index)
		}
		guard finals == [maxIndex] else {
			throw SEALError.incompleteSegmentSet
		}
	}

	private var snapshotAuthenticator: MaskedMultisetHash? {
		configuration.snapID == SnapID.maskedMultisetHash
			? MaskedMultisetHash(schedule: schedule) : nil
	}
}
