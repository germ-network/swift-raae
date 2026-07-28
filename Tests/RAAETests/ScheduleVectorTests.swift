import Foundation
import Testing

@testable import RAAE

@Suite("Payload schedule + single segment vs Appendix F.1")
struct ScheduleVectorTests {
	/// Build the F.1 schedule from the vendored vector.
	func loadF1() throws -> (schedule: PayloadSchedule, json: [String: Any]) {
		let v = try Vectors.load("F1")
		return (try Vectors.schedule(from: v), v)
	}

	@Test func scheduleMatchesVector() throws {
		let (schedule, v) = try loadF1()
		let sched = v["schedule"] as! [String: Any]
		#expect(Hex.encode(schedule.commitment) == sched["commitment_hex"] as! String)
		#expect(keyHex(schedule.payloadKey) == sched["payload_key_hex"] as! String)
		#expect(keyHex(schedule.snapKey) == sched["acc_key_hex"] as! String)
	}

	@Test func segmentAADMatchesVector() throws {
		let (schedule, v) = try loadF1()
		let seg = v["segment_0"] as! [String: Any]
		let aad = Segment.aadRandomMode(
			position: .init(index: 0, isFinal: true), associatedData: [],
			kdf: schedule.kdf)
		#expect(Hex.encode(aad) == seg["segment_aad_hex"] as! String)
	}

	/// Decrypting the vector's ciphertext proves segment_key, nonce, and AAD are all
	/// correct (the AEAD tag binds them); then re-encrypting under the fixed nonce pins
	/// the ciphertext in both directions.
	@Test func segmentDecryptsAndReencryptsExactly() throws {
		let (schedule, v) = try loadF1()
		let seg = v["segment_0"] as! [String: Any]
		let nonce = Hex.decode(seg["nonce_hex"] as! String)
		let expectedCT =
			Hex.decode(seg["ciphertext_hex"] as! String)
			+ Hex.decode(seg["tag_hex"] as! String)
		let position = SegmentPosition(index: 0, isFinal: (seg["is_final"] as! Int) == 1)

		// Decrypt → recovers the (unpublished) plaintext; success authenticates the path.
		let plaintext = try Segment.decryptRandom(
			schedule: schedule, position: position,
			associatedData: [], nonce: nonce, ciphertext: expectedCT)
		#expect(plaintext.count == Hex.decode(seg["ciphertext_hex"] as! String).count)

		// Re-encrypt the recovered plaintext under the same fixed nonce ⇒ exact ct||tag.
		let (_, ct) = try Segment.encryptRandom(
			schedule: schedule, position: position,
			associatedData: [], plaintext: plaintext, nonce: nonce)
		#expect(Hex.encode(ct) == Hex.encode(expectedCT))
	}

	@Test func payloadInfoValidationRejectsBadParameters() {
		var info = PayloadInfo(
			aeadID: 2, segmentMax: 16384, kdfID: 1, snapID: 1,
			nonceMode: .random, epochLength: 1, salt: [UInt8](repeating: 4, count: 32))
		#expect(throws: Never.self) { try info.validate() }

		info.segmentMax = 4095
		#expect(throws: PayloadInfo.ValidationError.self) { try info.validate() }
		info.segmentMax = 12288  // not a power of two
		#expect(throws: PayloadInfo.ValidationError.self) { try info.validate() }
		info.segmentMax = 16384
		info.epochLength = 64
		#expect(throws: PayloadInfo.ValidationError.self) { try info.validate() }
	}
}
