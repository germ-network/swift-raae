import RAAE
import Testing

/// `nonce_mode` consistency (§4.4): the mode is committed into the key schedule, so
/// segments must be produced and consumed in that mode. Mixing modes under one schedule
/// would emit objects that contradict their committed `payload_info`.
@Suite("nonce_mode consistency")
struct NonceModeTests {
	func makeSchedule(aeadID: UInt16, nonceMode: PayloadInfo.NonceMode) throws
		-> PayloadSchedule
	{
		let info = PayloadInfo(
			aeadID: aeadID, segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: nonceMode, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: info)
	}

	@Test func randomOperationsRejectDerivedSchedule() throws {
		let schedule = try makeSchedule(aeadID: 0x001F, nonceMode: .derived)
		let pos = SegmentPosition(index: 0, isFinal: true)
		let nonce = Segment.freshNonce(for: schedule.aead)
		#expect(
			throws: Segment.SegmentError.nonceModeMismatch(scheduleMode: .derived)
		) {
			_ = try Segment.encryptRandom(
				schedule: schedule, position: pos, associatedData: [],
				plaintext: [1], nonce: nonce)
		}
		#expect(
			throws: Segment.SegmentError.nonceModeMismatch(scheduleMode: .derived)
		) {
			_ = try Segment.decryptRandom(
				schedule: schedule, position: pos, associatedData: [], nonce: nonce,
				ciphertext: [UInt8](repeating: 0, count: 17))
		}
	}

	@Test func derivedOperationsRejectRandomSchedule() throws {
		let schedule = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
		let pos = SegmentPosition(index: 0, isFinal: true)
		#expect(
			throws: Segment.SegmentError.nonceModeMismatch(scheduleMode: .random)
		) {
			_ = try Segment.encryptDerived(
				schedule: schedule, position: pos, associatedData: [],
				plaintext: [1])
		}
		#expect(
			throws: Segment.SegmentError.nonceModeMismatch(scheduleMode: .random)
		) {
			_ = try Segment.decryptDerived(
				schedule: schedule, position: pos, associatedData: [],
				ciphertext: [UInt8](repeating: 0, count: 17))
		}
	}

	@Test func meteredPathsInheritTheGuard() throws {
		let derived = try makeSchedule(aeadID: 0x001F, nonceMode: .derived)
		#expect(
			throws: Segment.SegmentError.nonceModeMismatch(scheduleMode: .derived)
		) {
			_ = try PayloadEncryptor(schedule: derived).encryptRandom(
				position: SegmentPosition(index: 0, isFinal: true),
				associatedData: [], plaintext: [1])
		}
		let random = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
		#expect(
			throws: Segment.SegmentError.nonceModeMismatch(scheduleMode: .random)
		) {
			_ = try PayloadEncryptor(schedule: random).encryptDerived(
				position: SegmentPosition(index: 0, isFinal: true),
				associatedData: [], plaintext: [1])
		}
	}
}
