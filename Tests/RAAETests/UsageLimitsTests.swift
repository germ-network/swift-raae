import RAAE
import Testing

/// §5.9 usage budgets — the informational bounds the SEAL writer meters (writer
/// behavior is covered in `SEALTests`).
@Suite("Usage limits")
struct UsageLimitsTests {
	func schedule(aeadID: UInt16, nonceMode: PayloadInfo.NonceMode, segmentMax: UInt32 = 65536)
		throws -> PayloadSchedule
	{
		let info = PayloadInfo(
			aeadID: aeadID, segmentMax: segmentMax, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: nonceMode, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: [UInt8](repeating: 0xAA, count: 32),
			payloadInfo: info)
	}

	// MARK: budget numbers (§5.9.3 Table 15, §5.9.7)

	@Test func randomModeBudgets() throws {
		// 96-bit nonce, 2^-32 target ⇒ ~2^32 per epoch key; no per-segment cap.
		for id in [UInt16(0x0001), 0x0002, 0x001D] {
			let b = try schedule(aeadID: id, nonceMode: .random).usageBudget()
			#expect(b.perEpochKeyLog2 == 32)
			#expect(b.perSegmentLog2 == nil)
		}
		// AES-128-GCM has the 128-bit-key epoch-key-collision floor; 256-bit suites don't.
		#expect(
			try schedule(aeadID: 0x0001, nonceMode: .random).usageBudget()
				.maxEpochKeysLog2 == 48)
		#expect(
			try schedule(aeadID: 0x0002, nonceMode: .random).usageBudget()
				.maxEpochKeysLog2 == nil)
		#expect(
			try schedule(aeadID: 0x001D, nonceMode: .random).usageBudget()
				.maxEpochKeysLog2 == nil)
	}

	@Test func derivedModeBudgets() throws {
		// AES-256-GCM-SIV: 2^48 distinct nonces per epoch key; hot-segment cap = 48 - log2(L).
		let b64k = try schedule(aeadID: 0x001F, nonceMode: .derived, segmentMax: 65536)
			.usageBudget()
		#expect(b64k.perEpochKeyLog2 == 48)
		#expect(b64k.perSegmentLog2 == 36)  // L = 4096 ⇒ 48 - 12
		#expect(b64k.maxEpochKeysLog2 == nil)
		let b16k = try schedule(aeadID: 0x001F, nonceMode: .derived, segmentMax: 16384)
			.usageBudget()
		#expect(b16k.perSegmentLog2 == 38)  // L = 1024 ⇒ 48 - 10
	}

	@Test func writeOnceDerivedBudgets() throws {
		// Non-MRAE derived is only constructible under SEAL-RO-v1 (§4.5.3.2); the
		// budget is the write-once discipline itself: one encryption per segment,
		// and the 2^r segment indices an epoch key covers. Table 13 pins RO to
		// snap_id 0x0000.
		let info = PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: SnapID.none,
			nonceMode: .derived, epochLength: 3,
			salt: [UInt8](repeating: 0x04, count: 32))
		let sched = try PayloadSchedule(
			protocolID: ProtocolID.immutable, cek: [UInt8](repeating: 0xAA, count: 32),
			payloadInfo: info)
		let b = sched.usageBudget()
		#expect(b.perEpochKeyLog2 == 3)
		#expect(b.perSegmentLog2 == 0)
		#expect(b.maxEpochKeysLog2 == nil)
	}
}
