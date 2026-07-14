import RAAE
import Testing

@testable import SEAL

/// The Stage-C rewriter: `RewriteSeg` over a verified `SEAL-RW-v1` object (§4.9.2),
/// with the accumulator recovered internally by unmasking the snapshot and the §5.9
/// budgets continued from the persisted ``SEALUsageState``.
@Suite("SEAL rewriter")
struct SEALRewriteTests {
	/// Byte-exact engine KAT against Appendix F.17.1 (AES-256-GCM-SIV, derived,
	/// 65536): GCM-SIV is deterministic, so the engine rewrite of segment 0 with the
	/// vector's replacement plaintext must reproduce the vector's replacement
	/// `ct||tag` and new snapshot exactly — pinning the resume-verify path, the
	/// unmask-based accumulator recovery, and the O(1) rewrite update end to end.
	@Test func rewriteMatchesF17Vector() throws {
		let v = try Vectors.load("F17")
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x001F, kdfID: 0x0001, segmentMax: 65536,
			epochLength: 0)
		let cek = Hex.decode(v["cek_hex"] as! String)
		let header = SealedObjectHeader(
			payloadInfo: Vectors.payloadInfo(from: v),
			commitment: Hex.decode(
				(v["schedule"] as! [String: Any])["commitment_hex"] as! String))
		let segments = Vectors.sealedSegments(from: v)
		let snapshot = Vectors.snapshot(from: v)
		// epoch_length 0 ⇒ one epoch per index; each segment written once.
		let usage = SEALUsageState(
			epochCounts: [0: 1, 1: 1], segmentWrites: [0: 1, 1: 1])

		// Recover the vector's replacement plaintext by decrypting its rewritten
		// segment (the vectors print ciphertext, not plaintext).
		let rewriteBlock = v["rewrite_segment_0"] as! [String: Any]
		let vectorReplacement = SealedSegment(
			position: SegmentPosition(
				index: 0, isFinal: (rewriteBlock["is_final"] as! Int) == 1),
			nonce: nil,
			ciphertext: Hex.decode(rewriteBlock["new_ciphertext_hex"] as! String)
				+ Hex.decode(rewriteBlock["new_tag_hex"] as! String))
		let reader = try config.startDecryption(cek: cek, header: header)
		let newPlaintext = try reader.decrypt(vectorReplacement)

		let rewriter = try config.resumeWriting(
			cek: cek, header: header, snapshot: snapshot, segments: segments,
			usageState: usage)
		// Determinism check first: rewriting with the ORIGINAL plaintext reproduces
		// the original segment and leaves the snapshot unchanged.
		let originalPlaintext = try reader.decrypt(segments[0])
		let (same, sameSnapshot) = try rewriter.rewrite(
			originalPlaintext, replacing: segments[0])
		#expect(same == segments[0])
		#expect(sameSnapshot == snapshot)
		// The vector rewrite: byte-exact replacement and snapshot.
		let (replacement, newSnapshot) = try rewriter.rewrite(
			newPlaintext, replacing: segments[0])
		#expect(
			Hex.encode(replacement.ciphertext)
				== (rewriteBlock["new_ciphertext_hex"] as! String)
				+ (rewriteBlock["new_tag_hex"] as! String))
		#expect(
			Hex.encode(newSnapshot)
				== (rewriteBlock["new_wrapped_acc_hex"] as! String)
				+ (rewriteBlock["new_snapshot_tag_hex"] as! String))
		// Counters advanced across both rewrites.
		#expect(rewriter.usageState.segmentWrites[0] == 3)
	}

	/// The random-mode path over real vector state (F.16.1): resume verifies, the
	/// rewrite round-trips under a fresh nonce, the old snapshot dies, and stale
	/// segment copies are rejected.
	@Test func randomModeRewriteLifecycleOverF16Vector() throws {
		let v = try Vectors.load("F16")
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 65536,
			epochLength: 1)
		let cek = Hex.decode(v["cek_hex"] as! String)
		let header = SealedObjectHeader(
			payloadInfo: Vectors.payloadInfo(from: v),
			commitment: Hex.decode(
				(v["schedule"] as! [String: Any])["commitment_hex"] as! String))
		let segments = Vectors.sealedSegments(from: v)
		let snapshot = Vectors.snapshot(from: v)
		// epoch_length 1 ⇒ indices 0,1 share epoch 0.
		let usage = SEALUsageState(
			epochCounts: [0: 2], segmentWrites: [0: 1, 1: 1])

		let reader = try config.startDecryption(cek: cek, header: header)
		let rewriteBlock = v["rewrite_segment_0"] as! [String: Any]
		let newPlaintext = try reader.decrypt(
			SealedSegment(
				position: SegmentPosition(
					index: 0, isFinal: (rewriteBlock["is_final"] as! Int) == 1),
				nonce: Hex.decode(rewriteBlock["new_nonce_hex"] as! String),
				ciphertext: Hex.decode(
					rewriteBlock["new_ciphertext_hex"] as! String)
					+ Hex.decode(rewriteBlock["new_tag_hex"] as! String)))

		let rewriter = try config.resumeWriting(
			cek: cek, header: header, snapshot: snapshot, segments: segments,
			usageState: usage)
		let (replacement, newSnapshot) = try rewriter.rewrite(
			newPlaintext, replacing: segments[0])
		// Fresh random nonce ⇒ new bytes, but the plaintext and set semantics hold.
		#expect(try reader.decrypt(replacement) == newPlaintext)
		try reader.verifySnapshot(newSnapshot, segments: [replacement, segments[1]])
		#expect(throws: SEALError.snapshotMismatch) {
			try reader.verifySnapshot(snapshot, segments: [replacement, segments[1]])
		}
		// The pre-rewrite copy of segment 0 is stale: its tag left the verified set.
		#expect(throws: SEALError.segmentNotInVerifiedSet(0)) {
			_ = try rewriter.rewrite([1, 2, 3], replacing: segments[0])
		}
		#expect(rewriter.usageState.epochCounts[0] == 3)
	}

	@Test func resumeRefusesWriteOnceAndBadSnapshots() throws {
		// SEAL-RO-v1: "an encryptor MUST NOT rewrite a segment once written."
		let ro = try SEALConfiguration(profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001)
		let roCEK = SEALConfiguration.generateCEK()
		let roWriter = try ro.startEncryption(cek: roCEK)
		let roSegment = try roWriter.encrypt(
			[1], at: SegmentPosition(index: 0, isFinal: true))
		let roObject = try roWriter.finalize()
		#expect(throws: SEALError.writeOnceProfileForbidsRewrite) {
			_ = try ro.resumeWriting(
				cek: roCEK, header: roObject.header, snapshot: [],
				segments: [roSegment], usageState: roObject.usageState)
		}

		// RW: a snapshot that does not match the presented set refuses to resume.
		let rw = try SEALConfiguration(profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001)
		let cek = SEALConfiguration.generateCEK()
		let writer = try rw.startEncryption(cek: cek)
		let segment = try writer.encrypt(
			[1], at: SegmentPosition(index: 0, isFinal: true))
		let object = try writer.finalize()
		var wrongSnapshot = object.snapshot!
		wrongSnapshot[0] ^= 1
		#expect(throws: SEALError.snapshotMismatch) {
			_ = try rw.resumeWriting(
				cek: cek, header: object.header, snapshot: wrongSnapshot,
				segments: [segment], usageState: object.usageState)
		}
	}

	@Test func rewriteBudgetsAreHardStops() throws {
		// Derived MRAE hot-rewrite cap (§5.9.7.4): advantage 2^-106 ⇒ birthday 11;
		// segmentMax 16384 ⇒ log2 L = 10 ⇒ perSegmentLog2 = 1 ⇒ 2 encryptions per
		// segment. The authoring write used one; the first rewrite is the second and
		// last, the next throws.
		let siv = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x001F, kdfID: 0x0001, segmentMax: 16384)
		let cek = SEALConfiguration.generateCEK()
		let writer = try siv.startEncryption(cek: cek)
		let segment = try writer.encrypt(
			[1], at: SegmentPosition(index: 0, isFinal: true))
		let object = try writer.finalize()
		let rewriter = try SEALConfiguration.resumeWritingForTesting(
			configuration: siv, cek: cek, header: object.header,
			snapshot: object.snapshot!, segments: [segment],
			usageState: object.usageState, advantageLog2: 106)
		let (replacement, _) = try rewriter.rewrite([2], replacing: segment)
		#expect(throws: SEALError.segmentBudgetExceeded(index: 0, limitLog2: 1)) {
			_ = try rewriter.rewrite([3], replacing: replacement)
		}

		// Random-mode epoch cap: advantage 2^-91 ⇒ 8 per epoch key; the authoring
		// pass already spent all 8 (epochLength 4 ⇒ indices 0..7 share epoch 0).
		let gcm = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, epochLength: 4)
		let gcmCEK = SEALConfiguration.generateCEK()
		let gcmWriter = try gcm.startEncryption(cek: gcmCEK)
		var segments: [SealedSegment] = []
		for i in 0..<8 {
			segments.append(
				try gcmWriter.encrypt(
					[1], at: SegmentPosition(index: UInt64(i), isFinal: i == 7))
			)
		}
		let gcmObject = try gcmWriter.finalize()
		let gcmRewriter = try SEALConfiguration.resumeWritingForTesting(
			configuration: gcm, cek: gcmCEK, header: gcmObject.header,
			snapshot: gcmObject.snapshot!, segments: segments,
			usageState: gcmObject.usageState, advantageLog2: 91)
		#expect(throws: SEALError.epochBudgetExceeded(epochIndex: 0, limitLog2: 3)) {
			_ = try gcmRewriter.rewrite([2], replacing: segments[0])
		}
	}
}
