import Crypto
import Testing

@testable import RAAE

/// The swift-crypto 5.0 span fast path and the pre-5.0 array path must agree
/// byte-for-byte — the whole point of the custody change is that it moves *where* a
/// secret lives, never what the derivation or the AEAD computes. `forceArrayPath`
/// selects the array path at every decision point, so one process can diff the two
/// against each other and against the published Appendix F bytes.
///
/// `.serialized`: the seam is process-global.
@Suite("Array path vs span path equivalence", .serialized)
struct PathEquivalenceTests {
	/// F.1 (`SEAL-RW-v1`, random nonce, AES-256-GCM) inputs.
	func f1() throws -> (info: PayloadInfo, cek: SymmetricKey, seg: [String: Any]) {
		let v = try Vectors.load("F1")
		return (
			Vectors.payloadInfo(from: v),
			SymmetricKey(data: Hex.decode(v["cek_hex"] as! String)),
			v["segment_0"] as! [String: Any]
		)
	}

	@Test func scheduleMatchesF1OnBothPaths() throws {
		let (info, cek, _) = try f1()
		let v = try Vectors.load("F1")
		let published = v["schedule"] as! [String: Any]

		// `defer` so a throw mid-test cannot leave the process-global seam flipped and
		// silently downgrade every later test to the array path.
		defer { forceArrayPath = false }
		for useArrayPath in [false, true] {
			forceArrayPath = useArrayPath
			let schedule = try PayloadSchedule(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
			#expect(
				Hex.encode(schedule.commitment) == published["commitment_hex"]
					as! String)
			#expect(
				keyHex(schedule.payloadKey) == published["payload_key_hex"]
					as! String)
			#expect(keyHex(schedule.snapKey) == published["acc_key_hex"] as! String)
		}
	}

	@Test func randomModeSegmentAgreesAcrossPaths() throws {
		let (info, cek, seg) = try f1()
		let nonce = Hex.decode(seg["nonce_hex"] as! String)
		let isFinal = (seg["is_final"] as! Int) == 1
		let published =
			Hex.decode(seg["ciphertext_hex"] as! String)
			+ Hex.decode(seg["tag_hex"] as! String)

		func decryptThenReencrypt() throws -> (plaintext: [UInt8], ciphertext: [UInt8]) {
			let schedule = try PayloadSchedule(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
			let position = SegmentPosition(index: 0, isFinal: isFinal)
			let plaintext = try Segment.decryptRandom(
				schedule: schedule, position: position, associatedData: [],
				nonce: nonce, ciphertext: published)
			let reencrypted = try Segment.encryptRandom(
				schedule: schedule, position: position, associatedData: [],
				plaintext: plaintext, nonce: nonce
			).ciphertext
			return (plaintext, reencrypted)
		}

		defer { forceArrayPath = false }
		forceArrayPath = false
		let span = try decryptThenReencrypt()
		forceArrayPath = true
		let array = try decryptThenReencrypt()

		#expect(span.plaintext == array.plaintext)
		#expect(span.ciphertext == array.ciphertext)
		#expect(span.ciphertext == published)
	}

	@Test func chachaSegmentAgreesAcrossPaths() throws {
		// The F.1 case above exercises AES-256-GCM. ChaChaPoly has its own span path,
		// so diff it too; AES-128-GCM shares the GCM fast path (residual risk only in
		// the 16-octet key length) and `AES.GCM._SIV` has no span surface at all.
		let info = PayloadInfo(
			aeadID: 0x001D, segmentMax: 16384, kdfID: 0x0001,
			snapID: SnapID.maskedMultisetHash, nonceMode: .random, epochLength: 16,
			salt: [UInt8](repeating: 0x07, count: 32))
		let cek = SymmetricKey(data: [UInt8](repeating: 0x44, count: 32))
		let plaintext = [UInt8](repeating: 0x2C, count: 96)
		let nonce = [UInt8](repeating: 0x5E, count: 12)
		let position = SegmentPosition(index: 5, isFinal: true)

		func sealThenOpen() throws -> (ciphertext: [UInt8], plaintext: [UInt8]) {
			let schedule = try PayloadSchedule(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
			let ciphertext = try Segment.encryptRandom(
				schedule: schedule, position: position, associatedData: [],
				plaintext: plaintext, nonce: nonce
			).ciphertext
			let opened = try Segment.decryptRandom(
				schedule: schedule, position: position, associatedData: [],
				nonce: nonce, ciphertext: ciphertext)
			return (ciphertext, opened)
		}

		defer { forceArrayPath = false }
		forceArrayPath = false
		let span = try sealThenOpen()
		forceArrayPath = true
		let array = try sealThenOpen()

		#expect(span.ciphertext == array.ciphertext)
		#expect(span.plaintext == array.plaintext)
		#expect(span.plaintext == plaintext)
	}

	@Test func derivedModeScheduleAndSegmentAgreeAcrossPaths() throws {
		// Derived + MRAE (`SEAL-compact`-shaped): exercises `nonce_base` derivation and
		// the in-place AES-GCM-SIV path, which has no span surface and must be identical.
		let info = PayloadInfo(
			aeadID: 0x001F, segmentMax: 16384, kdfID: 0x0001,
			snapID: SnapID.maskedMultisetHash, nonceMode: .derived, epochLength: 16,
			salt: [UInt8](repeating: 0x03, count: 32))
		let cek = SymmetricKey(data: [UInt8](repeating: 0x11, count: 32))
		let plaintext = [UInt8](repeating: 0x5A, count: 64)

		func deriveAndEncrypt() throws -> (commitment: [UInt8], key: String, ct: [UInt8]) {
			let schedule = try PayloadSchedule(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
			let ct = try Segment.encryptDerivedUnmetered(
				schedule: schedule,
				position: SegmentPosition(index: 3, isFinal: true),
				associatedData: [], plaintext: plaintext)
			return (schedule.commitment, keyHex(schedule.nonceBase!), ct)
		}

		defer { forceArrayPath = false }
		forceArrayPath = false
		let span = try deriveAndEncrypt()
		forceArrayPath = true
		let array = try deriveAndEncrypt()

		#expect(span.commitment == array.commitment)
		#expect(span.key == array.key)
		#expect(span.ct == array.ct)
	}
}
