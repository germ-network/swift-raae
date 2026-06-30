import Foundation
import Testing

@testable import RAAE

@Suite("Masked multiset hash snapshot (§4.7.4)")
struct SnapshotVectorTests {
	/// Map a vector segment dict to the `(index, tag)` pair the snapshot consumes.
	func tagPair(_ seg: [String: Any]) -> (index: UInt64, tag: [UInt8]) {
		(UInt64(seg["index"] as! Int), Hex.decode(seg["tag_hex"] as! String))
	}

	@Test func singleSegmentSnapshotMatchesE1() throws {
		let v = try Vectors.load("E1")
		let hash = MaskedMultisetHash(schedule: try Vectors.schedule(from: v))
		let seg = v["segment_0"] as! [String: Any]
		let snap = v["snapshot"] as! [String: Any]
		let tag = Hex.decode(seg["tag_hex"] as! String)

		let contrib = hash.contribution(index: 0, tag: tag)
		#expect(Hex.encode(contrib) == seg["contrib_hex"] as! String)

		let acc = hash.accumulator(segments: [(UInt64(0), tag)])
		#expect(Hex.encode(acc) == snap["accumulator_hex"] as! String)
		#expect(
			Hex.encode(hash.snapshotTag(segmentCount: 1, accumulator: acc)) == snap[
				"snapshot_tag_hex"] as! String)

		let snapTag = Hex.decode(snap["snapshot_tag_hex"] as! String)
		#expect(
			Hex.encode(hash.mask(segmentCount: 1, snapshotTag: snapTag)) == snap[
				"mask_hex"] as! String)

		let value = hash.snapshotValue(segmentCount: 1, accumulator: acc)
		let expected = Hex.decode(snap["wrapped_acc_hex"] as! String) + snapTag
		#expect(Hex.encode(value) == Hex.encode(expected))
		#expect(hash.verify(snapshot: value, segments: [(UInt64(0), tag)]))
	}

	@Test func twoSegmentSnapshotMatchesE7AndDetectsTampering() throws {
		let v = try Vectors.load("E7")
		let hash = MaskedMultisetHash(schedule: try Vectors.schedule(from: v))
		let segs = (v["segments"] as! [[String: Any]]).map(tagPair)
		let snap = v["snapshot"] as! [String: Any]

		let acc = hash.accumulator(segments: segs)
		#expect(Hex.encode(acc) == snap["accumulator_hex"] as! String)
		let value = hash.snapshotValue(segmentCount: 2, accumulator: acc)
		let expected =
			Hex.decode(snap["wrapped_acc_hex"] as! String)
			+ Hex.decode(snap["snapshot_tag_hex"] as! String)
		#expect(Hex.encode(value) == Hex.encode(expected))

		// Accepts the intact set, in any order (XOR is order-independent).
		#expect(hash.verify(snapshot: value, segments: segs))
		#expect(hash.verify(snapshot: value, segments: segs.reversed()))

		// Rejects a modified tag, a dropped segment, and an added segment.
		var tampered = segs
		tampered[0].tag[0] ^= 0x01
		#expect(!hash.verify(snapshot: value, segments: tampered))
		#expect(!hash.verify(snapshot: value, segments: [segs[0]]))
		#expect(!hash.verify(snapshot: value, segments: segs + [(UInt64(2), segs[0].tag)]))
	}

	@Test func rewriteUpdatesSnapshotMatchingE14() throws {
		let v = try Vectors.load("E14")
		let schedule = try Vectors.schedule(from: v)
		let hash = MaskedMultisetHash(schedule: schedule)
		let segs = (v["segments"] as! [[String: Any]]).map(tagPair)
		let snap = v["snapshot"] as! [String: Any]
		let rw = v["rewrite_segment_0"] as! [String: Any]

		// Base snapshot matches.
		let baseAcc = hash.accumulator(segments: segs)
		#expect(Hex.encode(baseAcc) == snap["accumulator_hex"] as! String)

		// Re-encrypt segment 0's replacement under the fresh nonce ⇒ exact new ct||tag.
		let newNonce = Hex.decode(rw["new_nonce_hex"] as! String)
		let newCTTag =
			Hex.decode(rw["new_ciphertext_hex"] as! String)
			+ Hex.decode(rw["new_tag_hex"] as! String)
		let pos = SegmentPosition(index: 0, isFinal: (rw["is_final"] as! Int) == 1)
		let newPlaintext = try Segment.decryptRandom(
			schedule: schedule, position: pos, associatedData: [], nonce: newNonce,
			ciphertext: newCTTag)
		let (_, reCT) = try Segment.encryptRandom(
			schedule: schedule, position: pos, associatedData: [],
			plaintext: newPlaintext, nonce: newNonce)
		#expect(Hex.encode(reCT) == Hex.encode(newCTTag))

		// New contribution and O(1) accumulator update match the vector.
		let newTag = Hex.decode(rw["new_tag_hex"] as! String)
		#expect(
			Hex.encode(hash.contribution(index: 0, tag: newTag)) == rw[
				"new_contrib_hex"] as! String)
		let newAcc = hash.rewrittenAccumulator(
			accumulator: baseAcc, index: 0, oldTag: segs[0].tag, newTag: newTag)
		#expect(Hex.encode(newAcc) == rw["new_accumulator_hex"] as! String)

		// New published snapshot matches, and verifies against the rewritten segment set.
		let newValue = hash.snapshotValue(segmentCount: 2, accumulator: newAcc)
		let expected =
			Hex.decode(rw["new_wrapped_acc_hex"] as! String)
			+ Hex.decode(rw["new_snapshot_tag_hex"] as! String)
		#expect(Hex.encode(newValue) == Hex.encode(expected))
		#expect(hash.verify(snapshot: newValue, segments: [(UInt64(0), newTag), segs[1]]))
	}

	@Test func negativeSnapVerifyRejectsTamperedAccumulatorE17() throws {
		let v = try Vectors.load("E14")
		let hash = MaskedMultisetHash(schedule: try Vectors.schedule(from: v))
		let neg = v["negative_snapverify"] as! [String: Any]
		let snap = v["snapshot"] as! [String: Any]

		// Recomputing the tag over the tampered accumulator differs from the stored one.
		let tamperedAcc = Hex.decode(neg["tampered_accumulator_hex"] as! String)
		let storedTag = Hex.decode(snap["snapshot_tag_hex"] as! String)
		let recomputed = hash.snapshotTag(segmentCount: 2, accumulator: tamperedAcc)
		#expect(!ConstantTime.equals(recomputed, storedTag))
	}
}

@Suite("Constant-time comparison")
struct ConstantTimeTests {
	@Test func equalAndUnequal() {
		#expect(ConstantTime.equals([1, 2, 3], [1, 2, 3]))
		#expect(!ConstantTime.equals([1, 2, 3], [1, 2, 4]))
		#expect(!ConstantTime.equals([1, 2, 3], [1, 2]))
		#expect(ConstantTime.equals([], []))
	}
}
