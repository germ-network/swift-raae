import RAAE
import Testing

@testable import SEAL

/// End-to-end engine lifecycle per the spec's write/read paths (§4.9): StartEnc →
/// EncSeg* → snapshot, then StartDec → SnapVerify → DecSeg*. The byte-exactness of
/// every derivation the engine delegates to is pinned by the core's Appendix E
/// vector suites; these tests cover the engine's own guarantees.
@Suite("SEAL engine round trips")
struct SEALRoundTripTests {
	let plaintexts: [[UInt8]] = [[1, 2, 3], [4, 5], [6, 7, 8, 9]]

	func author(
		_ config: SEALConfiguration, cek: [UInt8], globalAssociatedData: [UInt8] = []
	) throws -> (object: SealedObject, segments: [SealedSegment]) {
		let writer = try config.startEncryption(
			cek: cek, globalAssociatedData: globalAssociatedData)
		var segments: [SealedSegment] = []
		for (i, pt) in plaintexts.enumerated() {
			segments.append(
				try writer.encrypt(
					pt,
					at: SegmentPosition(
						index: UInt64(i), isFinal: i == plaintexts.count - 1
					)))
		}
		return (try writer.finalize(), segments)
	}

	@Test func readWriteRandomModeLifecycle() throws {
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 16384,
			epochLength: 1)
		let cek = SEALConfiguration.generateCEK()
		let g = Array("demo-context".utf8)
		let (object, segments) = try author(config, cek: cek, globalAssociatedData: g)

		#expect(object.segmentCount == 3)
		#expect(segments.allSatisfy { $0.nonce?.count == 12 })  // Np = Nn in random mode

		// StartDec verifies the commitment: wrong CEK, wrong G, or omitted G fail.
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try config.startDecryption(
				cek: SEALConfiguration.generateCEK(), header: object.header,
				globalAssociatedData: g)
		}
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try config.startDecryption(cek: cek, header: object.header)
		}
		let reader = try config.startDecryption(
			cek: cek, header: object.header, globalAssociatedData: g)

		// SnapVerify accepts the recorded set (in any order) and every segment opens.
		try reader.verifySnapshot(object.snapshot!, segments: segments.reversed())
		for (i, segment) in segments.enumerated() {
			#expect(try reader.decrypt(segment) == plaintexts[i])
		}

		// Whole-object integrity: a dropped segment and a modified segment both fail.
		#expect(throws: SEALError.incompleteSegmentSet) {
			// Dropping the final segment leaves a set whose highest index is not final.
			try reader.verifySnapshot(
				object.snapshot!, segments: Array(segments.prefix(2)))
		}
		// Division of labor (§4.6/§4.7): the snapshot binds the tag multiset, so a
		// tag flip fails SnapVerify...
		var tagTampered = segments
		var tagCT = tagTampered[0].ciphertext
		tagCT[tagCT.count - 1] ^= 1
		tagTampered[0] = SealedSegment(
			position: segments[0].position, nonce: segments[0].nonce,
			ciphertext: tagCT)
		#expect(throws: SEALError.snapshotMismatch) {
			try reader.verifySnapshot(object.snapshot!, segments: tagTampered)
		}
		// ...while a ciphertext-body flip leaves the tags intact — SnapVerify passes
		// by design, and per-segment authenticity (the AEAD) rejects the segment.
		var bodyTampered = segments
		var bodyCT = bodyTampered[0].ciphertext
		bodyCT[0] ^= 1
		bodyTampered[0] = SealedSegment(
			position: segments[0].position, nonce: segments[0].nonce,
			ciphertext: bodyCT)
		try reader.verifySnapshot(object.snapshot!, segments: bodyTampered)
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decrypt(bodyTampered[0])
		}
	}

	@Test func readOnlyDerivedLifecycle() throws {
		// SEAL-RO-v1 + AES-256-GCM: the write-once pairing only the engine can author.
		let config = try SEALConfiguration(
			profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 16384)
		let cek = SEALConfiguration.generateCEK()
		let (object, segments) = try author(config, cek: cek)

		#expect(object.snapshot == nil)  // snap_id 0x0000: no snapshot authenticator
		#expect(segments.allSatisfy { $0.nonce == nil })  // Np = 0 in derived mode

		let reader = try config.startDecryption(cek: cek, header: object.header)
		#expect(throws: SEALError.noSnapshotAuthenticator) {
			try reader.verifySnapshot([], segments: segments)
		}
		// The finality rule is the sole truncation defense (§4.10.2).
		try reader.verifyFinality(positions: segments.map(\.position))
		#expect(throws: SEALError.incompleteSegmentSet) {
			try reader.verifyFinality(
				positions: segments.dropLast().map(\.position))
		}
		for (i, segment) in segments.enumerated() {
			#expect(try reader.decrypt(segment) == plaintexts[i])
		}
		// A segment presented at the wrong position fails authentication: position
		// and finality are bound through the derived nonce.
		let moved = SealedSegment(
			position: SegmentPosition(index: 1, isFinal: false), nonce: nil,
			ciphertext: segments[0].ciphertext)
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decrypt(moved)
		}
	}

	@Test func readWriteDerivedMRAELifecycle() throws {
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x001F, kdfID: 0x0001, segmentMax: 16384)
		let cek = SEALConfiguration.generateCEK()
		let (object, segments) = try author(config, cek: cek)
		#expect(segments.allSatisfy { $0.nonce == nil })
		let reader = try config.startDecryption(cek: cek, header: object.header)
		try reader.verifySnapshot(object.snapshot!, segments: segments)
		for (i, segment) in segments.enumerated() {
			#expect(try reader.decrypt(segment) == plaintexts[i])
		}
	}

	@Test func emptyObjectVerifies() throws {
		// §4.11.1: an empty object has zero segments and no final segment; the
		// snapshot covers the empty set.
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001)
		let cek = SEALConfiguration.generateCEK()
		let object = try config.startEncryption(cek: cek).finalize()
		#expect(object.segmentCount == 0)
		let reader = try config.startDecryption(cek: cek, header: object.header)
		try reader.verifySnapshot(object.snapshot!, segments: [])
	}

	@Test func writerEnforcesDiscipline() throws {
		let config = try SEALConfiguration(
			profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001)
		let writer = try config.startEncryption(cek: SEALConfiguration.generateCEK())
		_ = try writer.encrypt([1], at: SegmentPosition(index: 0, isFinal: false))

		// Each index exactly once — under RO this is the normative write-once rule.
		#expect(throws: SEALError.duplicateSegmentIndex(0)) {
			_ = try writer.encrypt([2], at: SegmentPosition(index: 0, isFinal: false))
		}
		// One final segment only.
		_ = try writer.encrypt([3], at: SegmentPosition(index: 2, isFinal: true))
		#expect(throws: SEALError.duplicateFinalSegment(existing: 2, new: 3)) {
			_ = try writer.encrypt([4], at: SegmentPosition(index: 3, isFinal: true))
		}
		// The engine index cap.
		#expect(throws: SEALError.segmentIndexExceedsCap(SEALLimits.maxSegments)) {
			_ = try writer.encrypt(
				[5],
				at: SegmentPosition(index: SEALLimits.maxSegments, isFinal: false))
		}
		// finalize() rejects a final segment that is not the highest index.
		_ = try writer.encrypt([6], at: SegmentPosition(index: 5, isFinal: false))
		#expect(throws: SEALError.malformedFinality(finalIndex: 2, maxIndex: 5)) {
			_ = try writer.finalize()
		}
	}

	@Test func finalizeIsTerminalAndRequiresFinality() throws {
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001)
		let writer = try config.startEncryption(cek: SEALConfiguration.generateCEK())
		_ = try writer.encrypt([1], at: SegmentPosition(index: 0, isFinal: false))
		// Non-empty object without a final segment.
		#expect(throws: SEALError.malformedFinality(finalIndex: nil, maxIndex: 0)) {
			_ = try writer.finalize()
		}
		_ = try writer.encrypt([2], at: SegmentPosition(index: 1, isFinal: true))
		_ = try writer.finalize()
		#expect(throws: SEALError.alreadyFinalized) { _ = try writer.finalize() }
		#expect(throws: SEALError.alreadyFinalized) {
			_ = try writer.encrypt([3], at: SegmentPosition(index: 2, isFinal: false))
		}
	}

	@Test func epochBudgetIsAHardStop() throws {
		// Shrink the budget through the internal test seam: advantage 2^-91 with a
		// 96-bit nonce ⇒ perEpochKeyLog2 = 3 ⇒ 8 encryptions per epoch key.
		// epochLength 4 puts 16 indices in epoch 0, so the 9th write trips the cap.
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, epochLength: 4)
		let writer = try SEALConfiguration.startEncryptionForTesting(
			configuration: config, cek: SEALConfiguration.generateCEK(),
			advantageLog2: 91)
		for i in 0..<8 {
			_ = try writer.encrypt(
				[1], at: SegmentPosition(index: UInt64(i), isFinal: false))
		}
		#expect(throws: SEALError.epochBudgetExceeded(epochIndex: 0, limitLog2: 3)) {
			_ = try writer.encrypt([1], at: SegmentPosition(index: 8, isFinal: false))
		}
	}

	@Test func oversizedPlaintextPropagatesCoreError() throws {
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 4096)
		let writer = try config.startEncryption(cek: SEALConfiguration.generateCEK())
		#expect(
			throws: Segment.SegmentError.exceedsSegmentMax(
				length: 4097, segmentMax: 4096)
		) {
			_ = try writer.encrypt(
				[UInt8](repeating: 0, count: 4097),
				at: SegmentPosition(index: 0, isFinal: true))
		}
	}

	@Test func nonceMetadataMismatchIsRejected() throws {
		// A derived-mode object whose segment carries a stray stored nonce (or a
		// random-mode segment missing one) is malformed.
		let derived = try SEALConfiguration(
			profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001)
		let cek = SEALConfiguration.generateCEK()
		let writer = try derived.startEncryption(cek: cek)
		let segment = try writer.encrypt([1], at: SegmentPosition(index: 0, isFinal: true))
		let object = try writer.finalize()
		let reader = try derived.startDecryption(cek: cek, header: object.header)
		#expect(throws: SEALError.nonceMetadataMismatch) {
			_ = try reader.decrypt(
				SealedSegment(
					position: segment.position,
					nonce: [UInt8](repeating: 0, count: 12),
					ciphertext: segment.ciphertext))
		}
	}
}
