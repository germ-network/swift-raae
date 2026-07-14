import Foundation
import Testing

@testable import RAAE

/// draft-sullivan-cfrg-raae-02 Appendix F.23: the `SEAL-simple(HKDF-SHA-256,
/// AES-256-GCM)` named instantiation end to end — `SEAL-RO-v1`, derived nonce,
/// `snap_id 0x0000`, epoch_length 32, `segment_max` 65536, empty `G`. AES-256-GCM
/// under a fixed derived nonce is deterministic, so re-encryption reproduces the
/// vector's ciphertext exactly. Every value was cross-checked against an independent
/// from-scratch implementation of the labeled KDF (§4.3/§4.5, Python hmac/hashlib).
@Suite("SEAL-simple named instantiation vs F.23")
struct SEALSimpleVectorTests {
	func loadF23() throws -> (PayloadSchedule, [String: Any]) {
		let v = try Vectors.load("F23")
		// SEAL-RO-v1 (write-once): Vectors.schedule pins SEAL-RW-v1, so build directly.
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.immutable, cek: Hex.decode(v["cek_hex"] as! String),
			payloadInfo: Vectors.payloadInfo(from: v))
		return (schedule, v)
	}

	@Test func scheduleMatchesVector() throws {
		let (schedule, v) = try loadF23()
		let s = v["schedule"] as! [String: Any]
		#expect(Hex.encode(schedule.commitment) == s["commitment_hex"] as! String)
		#expect(keyHex(schedule.payloadKey) == s["payload_key_hex"] as! String)
		#expect(schedule.nonceBase != nil)
		#expect(keyHex(schedule.nonceBase!) == s["nonce_base_hex"] as! String)
	}

	@Test func segmentDecryptsReencryptsAndAssemblesStoredObject() throws {
		let (schedule, v) = try loadF23()
		let seg = v["segment_0"] as! [String: Any]
		let pos = SegmentPosition(index: 0, isFinal: (seg["is_final"] as! Int) == 1)

		// The derived nonce is fixed by (index, is_final).
		let nonce = try Segment.derivedNonce(
			nonceBase: keyBytes(schedule.nonceBase!), position: pos)
		#expect(Hex.encode(nonce) == seg["nonce_hex"] as! String)

		// Decrypt recovers the (unpublished) plaintext; success authenticates the path.
		let ctTag = Vectors.ciphertextWithTag(seg)
		let pt = try Segment.decryptDerived(
			schedule: schedule, position: pos, associatedData: [], ciphertext: ctTag)
		// Re-encrypt under the fixed derived nonce ⇒ exact ct||tag. The write-once
		// non-MRAE pairing (§4.5.3.2) goes through the unmetered core seam — in
		// production the SEAL writer is the meter; the public metered static refuses it.
		let reCT = try Segment.encryptDerivedUnmetered(
			schedule: schedule, position: pos, associatedData: [], plaintext: pt)
		#expect(Hex.encode(reCT) == Hex.encode(ctTag))

		// Reduced immutable linear layout (§4.11.4): salt || commitment || ct || tag.
		let salt = Hex.decode((v["payload_info"] as! [String: Any])["salt_hex"] as! String)
		let stored = salt + schedule.commitment + reCT
		#expect(Hex.encode(stored) == v["stored_object_hex"] as! String)
	}
}
