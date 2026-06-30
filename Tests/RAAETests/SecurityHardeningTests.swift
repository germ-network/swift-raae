import RAAE
import Testing

/// Regression tests for the security-hardening pass (review findings H1, H2, M1).
@Suite("Security hardening")
struct SecurityHardeningTests {
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

	// MARK: H1 — over-large associated data must not collide in the segment AAD.

	@Test func largeAssociatedDataIsBoundDistinctly() throws {
		let kdf = SuiteRegistry.kdf(id: 0x0001)!
		let pos = SegmentPosition(index: 0, isFinal: true)
		// Two distinct values both larger than the 0xFFFE literal-framing limit.
		let a = [UInt8](repeating: 0x11, count: 70_000)
		var b = a
		b[69_999] = 0x22

		let aadA = Segment.aadRandomMode(position: pos, associatedData: a, kdf: kdf)
		let aadB = Segment.aadRandomMode(position: pos, associatedData: b, kdf: kdf)
		// Before the fix both framed to `0xFFFF` with an empty digest ⇒ identical.
		#expect(aadA != aadB)

		// End-to-end: decrypting under a different large A_i must fail authentication.
		let schedule = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
		let nonce = Segment.freshNonce(for: schedule.aead)
		let (_, ct) = try Segment.encryptRandom(
			schedule: schedule, position: pos, associatedData: a, plaintext: [1, 2, 3],
			nonce: nonce)
		#expect(throws: AEADError.authenticationFailure) {
			try Segment.decryptRandom(
				schedule: schedule, position: pos, associatedData: b, nonce: nonce,
				ciphertext: ct)
		}
		// ...and succeeds with the matching A_i.
		let pt = try Segment.decryptRandom(
			schedule: schedule, position: pos, associatedData: a, nonce: nonce,
			ciphertext: ct)
		#expect(pt == [1, 2, 3])
	}

	// MARK: H2 — derived nonce mode requires an MRAE AEAD.

	@Test func derivedModeWithNonMRAEIsRejected() {
		// AES-256-GCM (0x0002) is not MRAE ⇒ derived mode + rewrite would reuse a nonce.
		#expect(throws: PayloadSchedule.ScheduleError.derivedModeRequiresMRAE(0x0002)) {
			_ = try makeSchedule(aeadID: 0x0002, nonceMode: .derived)
		}
		// ChaCha20-Poly1305 (0x001D) is likewise non-MRAE.
		#expect(throws: PayloadSchedule.ScheduleError.derivedModeRequiresMRAE(0x001D)) {
			_ = try makeSchedule(aeadID: 0x001D, nonceMode: .derived)
		}
	}

	@Test func derivedModeWithMRAEIsAccepted() throws {
		// AES-256-GCM-SIV (0x001F) is MRAE ⇒ allowed.
		let schedule = try makeSchedule(aeadID: 0x001F, nonceMode: .derived)
		#expect(schedule.nonceBase != nil)
		// Random mode is unaffected for the same non-MRAE suite.
		_ = try makeSchedule(aeadID: 0x0002, nonceMode: .random)
	}

	// MARK: M1 — CEK must be exactly 32 octets.

	@Test func nonStandardCEKLengthIsRejected() {
		let info = PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: .random, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		for badLength in [0, 16, 31, 33, 64] {
			#expect(throws: PayloadSchedule.ScheduleError.invalidCEKLength(badLength)) {
				_ = try PayloadSchedule(
					protocolID: ProtocolID.mutable,
					cek: [UInt8](repeating: 0xAA, count: badLength),
					payloadInfo: info)
			}
		}
	}
}
