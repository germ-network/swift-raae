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
		var (cek, info, commitment, _) = try e1()
		_ = cek
		// Flip the LAST byte to exercise the non-early-exit constant-time compare.
		commitment[commitment.count - 1] ^= 0x01
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: commitment)
		}
	}

	@Test func startDecryptRejectsMutatedPayloadInfo() throws {
		var (cek, info, commitment, _) = try e1()
		_ = cek
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
