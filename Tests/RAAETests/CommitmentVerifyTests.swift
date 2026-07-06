import Foundation
import RAAE
import Testing

/// M2 — verify-before-decrypt as the default safe path (§4.6, §4.9.1.2).
@Suite("Commitment verification + startDecrypt")
struct CommitmentVerifyTests {
	/// E.1 inputs (public-surface): CEK, payload_info, published commitment, segment 0.
	func e1() throws -> (
		cek: [UInt8], info: PayloadInfo, commitment: [UInt8], seg: [String: Any]
	) {
		let v = try Vectors.load("E1")
		let pi = v["payload_info"] as! [String: Any]
		let info = PayloadInfo(
			aeadID: UInt16(pi["aead_id"] as! Int),
			segmentMax: UInt32(pi["segment_max"] as! Int),
			kdfID: UInt16(pi["kdf_id"] as! Int),
			snapID: UInt16(pi["snap_id"] as! Int),
			nonceMode: PayloadInfo.NonceMode(
				rawValue: UInt8(pi["nonce_mode"] as! Int))!,
			epochLength: UInt8(pi["epoch_length"] as! Int),
			salt: Hex.decode(pi["salt_hex"] as! String))
		let commitment = Hex.decode(
			(v["schedule"] as! [String: Any])["commitment_hex"] as! String)
		return (
			Hex.decode(v["cek_hex"] as! String), info, commitment,
			v["segment_0"] as! [String: Any]
		)
	}

	@Test func startDecryptAcceptsCorrectCommitmentAndDecrypts() throws {
		let (cek, info, commitment, seg) = try e1()
		let schedule = try PayloadSchedule.startDecrypt(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			publishedCommitment: commitment)
		#expect(schedule.commitment == commitment)
		// The safe path yields a usable schedule: E.1 segment 0 decrypts.
		let ctTag =
			Hex.decode(seg["ciphertext_hex"] as! String)
			+ Hex.decode(seg["tag_hex"] as! String)
		let pt = try Segment.decryptRandom(
			schedule: schedule, position: .init(index: 0, isFinal: true),
			associatedData: [], nonce: Hex.decode(seg["nonce_hex"] as! String),
			ciphertext: ctTag)
		#expect(pt.count == Hex.decode(seg["ciphertext_hex"] as! String).count)
	}

	@Test func startDecryptRejectsWrongCEK() throws {
		var (cek, info, commitment, _) = try e1()
		cek[0] ^= 0x01
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: commitment)
		}
	}

	@Test func startDecryptRejectsFlippedLastCommitmentByte() throws {
		let (cek, info, base, _) = try e1()
		var commitment = base
		// Flip the LAST byte to exercise the non-early-exit constant-time compare.
		commitment[commitment.count - 1] ^= 0x01
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: commitment)
		}
	}

	@Test func startDecryptRejectsMutatedPayloadInfo() throws {
		let (cek, base, commitment, _) = try e1()
		var info = base
		info.segmentMax = 65536  // valid pow2 ≥4096, but not what the commitment covers
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: commitment)
		}
	}

	@Test func startDecryptRejectsBelowMinimumCommitmentLength() throws {
		let (cek, info, _, _) = try e1()
		#expect(throws: PayloadSchedule.ScheduleError.commitmentTooShort(15)) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: [UInt8](repeating: 0, count: 15))
		}
	}

	@Test func startDecryptRejectsOverLongCommitmentWithoutCrashing() throws {
		let (cek, info, _, _) = try e1()
		// The published commitment is untrusted on the decrypt path. An over-long value must
		// fail as a typed error, not trap in Bytes.uint16 / HKDF.expand before verification.
		// 8161 exercises the HKDF window (> 255·Nh = 8160 for HKDF-SHA-256); 70000 the uint16
		// window (> 0xFFFF).
		for tooLong in [8161, 70_000] {
			#expect(throws: PayloadSchedule.ScheduleError.commitmentTooLong(tooLong)) {
				_ = try PayloadSchedule.startDecrypt(
					protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
					publishedCommitment: [UInt8](repeating: 0, count: tooLong))
			}
		}
	}

	@Test func initAcceptsCommitmentAtKDFMaximumAndRejectsOneMore() throws {
		let (cek, info, _, _) = try e1()
		// 255·Nh (8160 for HKDF-SHA-256) is the largest derivable commitment: it must derive
		// successfully, and one octet more must be rejected rather than crash.
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			commitmentLength: 8160)
		#expect(schedule.commitment.count == 8160)
		#expect(throws: PayloadSchedule.ScheduleError.commitmentTooLong(8161)) {
			_ = try PayloadSchedule(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				commitmentLength: 8161)
		}
	}

	@Test func verifyCommitmentRoundTripAndLengthMismatch() throws {
		let (cek, info, commitment, _) = try e1()
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
		try schedule.verifyCommitment(commitment)  // does not throw
		#expect(
			throws: PayloadSchedule.CommitmentError.commitmentLengthMismatch(
				expected: 32, got: 16)
		) {
			try schedule.verifyCommitment([UInt8](repeating: 0, count: 16))
		}
	}
}
