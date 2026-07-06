import RAAE
import Testing

/// `segment_max` enforcement (§4.4): a segment longer than `segment_max` is rejected on
/// both the encrypt and decrypt paths. Beyond conformance, the §5.9.7.4 per-segment
/// budget is computed from `segment_max` blocks per segment, so an oversized segment
/// would silently weaken the metered data-volume bound.
@Suite("segment_max enforcement")
struct SegmentMaxTests {
	/// Smallest legal segment_max, to keep test allocations small.
	static let segmentMax: UInt32 = 4096

	func makeSchedule(aeadID: UInt16, nonceMode: PayloadInfo.NonceMode) throws
		-> PayloadSchedule
	{
		let info = PayloadInfo(
			aeadID: aeadID, segmentMax: Self.segmentMax, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: nonceMode, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: info)
	}

	@Test func randomModeBoundary() throws {
		let schedule = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
		let pos = SegmentPosition(index: 0, isFinal: true)
		let nonce = Segment.freshNonce(for: schedule.aead)

		// Exactly segment_max octets is the largest legal segment and round-trips.
		let atMax = [UInt8](repeating: 0x5A, count: Int(Self.segmentMax))
		let (_, ct) = try Segment.encryptRandom(
			schedule: schedule, position: pos, associatedData: [], plaintext: atMax,
			nonce: nonce)
		let back = try Segment.decryptRandom(
			schedule: schedule, position: pos, associatedData: [], nonce: nonce,
			ciphertext: ct)
		#expect(back == atMax)

		// One octet over is rejected before any AEAD work.
		let overMax = [UInt8](repeating: 0x5A, count: Int(Self.segmentMax) + 1)
		#expect(
			throws: Segment.SegmentError.exceedsSegmentMax(
				length: overMax.count, segmentMax: Self.segmentMax)
		) {
			_ = try Segment.encryptRandom(
				schedule: schedule, position: pos, associatedData: [],
				plaintext: overMax, nonce: nonce)
		}
	}

	@Test func derivedModeBoundary() throws {
		// AES-256-GCM-SIV (0x001F) is the MRAE suite derived mode requires here.
		let schedule = try makeSchedule(aeadID: 0x001F, nonceMode: .derived)
		let pos = SegmentPosition(index: 0, isFinal: true)

		let atMax = [UInt8](repeating: 0x5A, count: Int(Self.segmentMax))
		let ct = try Segment.encryptDerived(
			schedule: schedule, position: pos, associatedData: [], plaintext: atMax)
		let back = try Segment.decryptDerived(
			schedule: schedule, position: pos, associatedData: [], ciphertext: ct)
		#expect(back == atMax)

		let overMax = [UInt8](repeating: 0x5A, count: Int(Self.segmentMax) + 1)
		#expect(
			throws: Segment.SegmentError.exceedsSegmentMax(
				length: overMax.count, segmentMax: Self.segmentMax)
		) {
			_ = try Segment.encryptDerived(
				schedule: schedule, position: pos, associatedData: [],
				plaintext: overMax)
		}
	}

	@Test func decryptRejectsOversizedCiphertextBeforeAuthentication() throws {
		// An oversized `ct||tag` fails with `exceedsSegmentMax`, not
		// `authenticationFailure`: the length check precedes any AEAD work, so a
		// decryptor never processes an over-limit segment.
		let oversized = [UInt8](
			repeating: 0, count: Int(Self.segmentMax) + 16 + 1)

		let random = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
		#expect(
			throws: Segment.SegmentError.exceedsSegmentMax(
				length: Int(Self.segmentMax) + 1, segmentMax: Self.segmentMax)
		) {
			_ = try Segment.decryptRandom(
				schedule: random,
				position: SegmentPosition(index: 0, isFinal: true),
				associatedData: [],
				nonce: [UInt8](repeating: 0, count: random.aead.nonceLength),
				ciphertext: oversized)
		}

		let derived = try makeSchedule(aeadID: 0x001F, nonceMode: .derived)
		#expect(
			throws: Segment.SegmentError.exceedsSegmentMax(
				length: Int(Self.segmentMax) + 1, segmentMax: Self.segmentMax)
		) {
			_ = try Segment.decryptDerived(
				schedule: derived,
				position: SegmentPosition(index: 0, isFinal: true),
				associatedData: [], ciphertext: oversized)
		}
	}

	@Test func meteredEncryptorInheritsEnforcement() throws {
		// PayloadEncryptor delegates to the Segment statics, so the metered path
		// rejects oversized segments identically.
		let schedule = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
		let encryptor = PayloadEncryptor(schedule: schedule)
		let overMax = [UInt8](repeating: 0x5A, count: Int(Self.segmentMax) + 1)
		#expect(
			throws: Segment.SegmentError.exceedsSegmentMax(
				length: overMax.count, segmentMax: Self.segmentMax)
		) {
			_ = try encryptor.encryptRandom(
				position: SegmentPosition(index: 0, isFinal: true),
				associatedData: [],
				plaintext: overMax,
				nonce: Segment.freshNonce(for: schedule.aead))
		}
	}
}
