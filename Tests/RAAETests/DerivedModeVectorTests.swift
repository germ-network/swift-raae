import Foundation
import Testing

@testable import RAAE

/// Byte-exact derived-nonce mode via AES-256-GCM-SIV, pinned to Appendix E.15.1.
/// GCM-SIV is deterministic, so re-encryption reproduces the vector ciphertext exactly.
@Suite("Derived mode + AES-256-GCM-SIV vs E.15.1")
struct DerivedModeVectorTests {
	func loadE15() throws -> (PayloadSchedule, [String: Any]) {
		let v = try Vectors.load("E15")
		return (try Vectors.schedule(from: v), v)
	}

	@Test func scheduleAndNonceBaseMatch() throws {
		let (schedule, v) = try loadE15()
		#expect(schedule.aead.id == 0x001F)
		let s = v["schedule"] as! [String: Any]
		#expect(Hex.encode(schedule.commitment) == s["commitment_hex"] as! String)
		#expect(keyHex(schedule.payloadKey) == s["payload_key_hex"] as! String)
		#expect(keyHex(schedule.snapKey) == s["acc_key_hex"] as! String)
		#expect(schedule.nonceBase != nil)
		#expect(keyHex(schedule.nonceBase!) == s["nonce_base_hex"] as! String)
	}

	@Test func segmentKeysAndDerivedNoncesMatch() throws {
		let (schedule, v) = try loadE15()
		for seg in v["segments"] as! [[String: Any]] {
			let index = UInt64(seg["index"] as! Int)
			let pos = SegmentPosition(
				index: index, isFinal: (seg["is_final"] as! Int) == 1)
			// epoch_length 0 ⇒ segment_key(i) = epoch_key(i), distinct per segment.
			#expect(
				keyHex(schedule.segmentKey(index: index)) == seg[
					"segment_key_hex"] as! String)
			let nonce = try Segment.derivedNonce(
				nonceBase: keyBytes(schedule.nonceBase!), position: pos)
			#expect(Hex.encode(nonce) == seg["nonce_hex"] as! String)
		}
	}

	@Test func segmentsDecryptAndReencryptExactly() throws {
		let (schedule, v) = try loadE15()
		for seg in v["segments"] as! [[String: Any]] {
			let pos = SegmentPosition(
				index: UInt64(seg["index"] as! Int),
				isFinal: (seg["is_final"] as! Int) == 1)
			let ctTag = Vectors.ciphertextWithTag(seg)
			let pt = try Segment.decryptDerived(
				schedule: schedule, position: pos, associatedData: [],
				ciphertext: ctTag)
			// GCM-SIV is deterministic ⇒ re-encryption yields the exact ct||tag.
			let reCT = try Segment.encryptDerived(
				schedule: schedule, position: pos, associatedData: [], plaintext: pt
			)
			#expect(Hex.encode(reCT) == Hex.encode(ctTag))
		}
	}

	@Test func snapshotAndDerivedRewriteMatch() throws {
		let (schedule, v) = try loadE15()
		let hash = MaskedMultisetHash(schedule: schedule)
		let segs = (v["segments"] as! [[String: Any]]).map {
			(
				index: UInt64($0["index"] as! Int),
				tag: Hex.decode($0["tag_hex"] as! String)
			)
		}
		let snap = v["snapshot"] as! [String: Any]
		let acc = hash.accumulator(segments: segs)
		#expect(Hex.encode(acc) == snap["accumulator_hex"] as! String)
		let value = hash.snapshotValue(segmentCount: 2, accumulator: acc)
		#expect(
			Hex.encode(value)
				== (snap["wrapped_acc_hex"] as! String)
				+ (snap["snapshot_tag_hex"] as! String))

		// Derived-mode rewrite of segment 0 reuses the SAME nonce (MRAE), recomputed.
		let rw = v["rewrite_segment_0"] as! [String: Any]
		let pos = SegmentPosition(index: 0, isFinal: (rw["is_final"] as! Int) == 1)
		let newCTTag =
			Hex.decode(rw["new_ciphertext_hex"] as! String)
			+ Hex.decode(rw["new_tag_hex"] as! String)
		let newPlaintext = try Segment.decryptDerived(
			schedule: schedule, position: pos, associatedData: [], ciphertext: newCTTag)
		let reCT = try Segment.encryptDerived(
			schedule: schedule, position: pos, associatedData: [],
			plaintext: newPlaintext)
		#expect(Hex.encode(reCT) == Hex.encode(newCTTag))

		let newTag = Hex.decode(rw["new_tag_hex"] as! String)
		let newAcc = hash.rewrittenAccumulator(
			accumulator: acc, index: 0, oldTag: segs[0].tag, newTag: newTag)
		#expect(Hex.encode(newAcc) == rw["new_accumulator_hex"] as! String)
		let newValue = hash.snapshotValue(segmentCount: 2, accumulator: newAcc)
		#expect(
			Hex.encode(newValue)
				== (rw["new_wrapped_acc_hex"] as! String)
				+ (rw["new_snapshot_tag_hex"] as! String))
	}
}
