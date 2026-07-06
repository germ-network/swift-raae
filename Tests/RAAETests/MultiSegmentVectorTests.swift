import Foundation
import Testing

@testable import RAAE

@Suite("Multi-segment + ChaCha20 + derived nonce")
struct MultiSegmentVectorTests {
	/// E.5 exercises the corrected ChaCha20-Poly1305 code point (0x001D).
	@Test func chaCha20SingleSegmentMatchesE5() throws {
		let v = try Vectors.load("E5")
		let schedule = try Vectors.schedule(from: v)
		#expect(schedule.aead.id == 0x001D)

		let sched = v["schedule"] as! [String: Any]
		#expect(Hex.encode(schedule.commitment) == sched["commitment_hex"] as! String)
		#expect(keyHex(schedule.payloadKey) == sched["payload_key_hex"] as! String)
		#expect(keyHex(schedule.snapKey) == sched["acc_key_hex"] as! String)

		let seg = v["segment_0"] as! [String: Any]
		let ctTag = Vectors.ciphertextWithTag(seg)
		let pos = SegmentPosition(index: 0, isFinal: true)
		let pt = try Segment.decryptRandom(
			schedule: schedule, position: pos, associatedData: [],
			nonce: Hex.decode(seg["nonce_hex"] as! String), ciphertext: ctTag)
		let (_, ct) = try Segment.encryptRandom(
			schedule: schedule, position: pos, associatedData: [],
			plaintext: pt, nonce: Hex.decode(seg["nonce_hex"] as! String))
		#expect(Hex.encode(ct) == Hex.encode(ctTag))
	}

	/// E.9 (two segments): each segment decrypts and re-encrypts exactly, and segments
	/// can be processed in any order (random access).
	@Test func twoSegmentsMatchE9InAnyOrder() throws {
		let v = try Vectors.load("E9")
		let schedule = try Vectors.schedule(from: v)
		let segs = v["segments"] as! [[String: Any]]

		// Decrypt in reverse order to demonstrate order independence.
		for seg in segs.reversed() {
			let pos = SegmentPosition(
				index: UInt64(seg["index"] as! Int),
				isFinal: (seg["is_final"] as! Int) == 1)
			let nonce = Hex.decode(seg["nonce_hex"] as! String)
			let ctTag = Vectors.ciphertextWithTag(seg)

			let aad = Segment.aadRandomMode(
				position: pos, associatedData: [], kdf: schedule.kdf)
			#expect(Hex.encode(aad) == seg["segment_aad_hex"] as! String)

			let pt = try Segment.decryptRandom(
				schedule: schedule, position: pos, associatedData: [],
				nonce: nonce, ciphertext: ctTag)
			let (_, ct) = try Segment.encryptRandom(
				schedule: schedule, position: pos, associatedData: [],
				plaintext: pt, nonce: nonce)
			#expect(Hex.encode(ct) == Hex.encode(ctTag))
		}
	}

	/// Different epoch indices yield different segment keys; same epoch shares a key
	/// (E.9 uses epoch_length=1, so segments 0 and 1 share epoch 0).
	@Test func epochKeyGroupingMatchesEpochLength() throws {
		let v = try Vectors.load("E9")
		let schedule = try Vectors.schedule(from: v)
		#expect(schedule.segmentKey(index: 0) == schedule.segmentKey(index: 1))  // epoch 0
		#expect(schedule.segmentKey(index: 0) != schedule.segmentKey(index: 2))  // epoch 1
	}
}

@Suite("Derived nonce mode (§4.5.3)")
struct DerivedNonceTests {
	/// `nonce(i) = nonce_base XOR ((i<<1)|is_final)` in the low octets.
	@Test func derivedNonceFormula() throws {
		let base = [UInt8](repeating: 0, count: 12)
		// i=0, is_final=1 → value 1 → last octet 0x01.
		let n0 = try Segment.derivedNonce(
			nonceBase: base, position: .init(index: 0, isFinal: true))
		#expect(n0 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
		// i=1, is_final=0 → value 2 → last octet 0x02.
		let n1 = try Segment.derivedNonce(
			nonceBase: base, position: .init(index: 1, isFinal: false))
		#expect(n1 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
		// XOR into a non-zero base flips only the low octets.
		let base2 = [UInt8](repeating: 0xFF, count: 12)
		let n2 = try Segment.derivedNonce(
			nonceBase: base2, position: .init(index: 0, isFinal: true))
		#expect(Array(n2.prefix(11)) == [UInt8](repeating: 0xFF, count: 11))
		#expect(n2.last == 0xFE)
	}

	@Test func nonceTooShortThrows() {
		#expect(throws: Segment.SegmentError.self) {
			try Segment.derivedNonce(
				nonceBase: [0, 0, 0, 0], position: .init(index: 0, isFinal: true))
		}
	}

	/// Derived-mode round-trip with AES-256-GCM-SIV (an MRAE suite, as the schedule now
	/// requires for derived mode). Distinct positions get distinct nonces, so this is
	/// also a self-consistency check on key/nonce/AAD derivation.
	@Test func derivedModeRoundTrips() throws {
		var info = Vectors.payloadInfo(from: try Vectors.load("E9"))
		info.nonceMode = .derived
		info.aeadID = 0x001F  // AES-256-GCM-SIV (MRAE)
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: info)
		#expect(schedule.nonceBase != nil)

		for (index, isFinal) in [(UInt64(0), false), (UInt64(1), true), (UInt64(5), false)]
		{
			let pos = SegmentPosition(index: index, isFinal: isFinal)
			let pt = Array("derived-mode segment \(index)".utf8)
			let ct = try Segment.encryptDerived(
				schedule: schedule, position: pos, associatedData: [0x01, 0x02],
				plaintext: pt)
			let back = try Segment.decryptDerived(
				schedule: schedule, position: pos, associatedData: [0x01, 0x02],
				ciphertext: ct)
			#expect(back == pt)
		}
	}

	@Test func derivedModeAADIsEmptyWithoutAssociatedData() {
		let kdf = SuiteRegistry.kdf(id: 0x0001)!
		#expect(Segment.aadDerivedMode(associatedData: [], kdf: kdf) == [])
		#expect(!Segment.aadDerivedMode(associatedData: [0x09], kdf: kdf).isEmpty)
	}
}
