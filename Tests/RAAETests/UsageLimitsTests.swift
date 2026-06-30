import RAAE
import Testing

/// M3 — usage budgets (§5.9) and the opt-in metering encryptor.
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

	// MARK: enforcement (use a high advantage target to shrink the budget for testing)

	@Test func enforceThrowsAtEpochBoundary() throws {
		let sched = try schedule(aeadID: 0x0002, nonceMode: .random)
		// advantageLog2 = 91 ⇒ perEpochKeyLog2 = (97 - 91)/2 = 3 ⇒ limit 2^3 = 8.
		let enc = PayloadEncryptor(schedule: sched, policy: .enforce, advantageLog2: 91)
		#expect(enc.budget.perEpochKeyLog2 == 3)
		let nonce = Segment.freshNonce(for: sched.aead)
		// 8 encryptions under epoch 0 (indices 0,1 share epoch with epochLength=1) succeed.
		for i in 0..<8 {
			_ = try enc.encryptRandom(
				position: .init(index: UInt64(i % 2), isFinal: false),
				associatedData: [],
				plaintext: [1], nonce: nonce)
		}
		#expect(enc.count(epochIndex: 0) == 8)
		// The 9th throws and does NOT advance the counter past the limit.
		#expect(throws: BudgetError.self) {
			_ = try enc.encryptRandom(
				position: .init(index: 0, isFinal: false), associatedData: [],
				plaintext: [1],
				nonce: nonce)
		}
		#expect(enc.count(epochIndex: 0) == 8)
	}

	@Test func warnPolicyEmitsEventButProceeds() throws {
		let sched = try schedule(aeadID: 0x0002, nonceMode: .random)
		let enc = PayloadEncryptor(schedule: sched, policy: .warn, advantageLog2: 95)
		// perEpochKeyLog2 = (97-95)/2 = 1 ⇒ limit 2 ⇒ the 3rd encryption trips warn.
		var events: [BudgetEvent] = []
		enc.onBudgetEvent = { events.append($0) }
		let nonce = Segment.freshNonce(for: sched.aead)
		for _ in 0..<3 {
			_ = try enc.encryptRandom(
				position: .init(index: 0, isFinal: false), associatedData: [],
				plaintext: [1],
				nonce: nonce)
		}
		#expect(enc.count(epochIndex: 0) == 3)  // proceeded past the budget
		#expect(events.count == 1 && events.first?.kind == .epochKey)
	}

	@Test func epochsAreCountedSeparately() throws {
		let sched = try schedule(aeadID: 0x0002, nonceMode: .random)  // epochLength = 1
		let enc = PayloadEncryptor(schedule: sched)
		let nonce = Segment.freshNonce(for: sched.aead)
		_ = try enc.encryptRandom(
			position: .init(index: 0, isFinal: false), associatedData: [],
			plaintext: [1], nonce: nonce)
		_ = try enc.encryptRandom(
			position: .init(index: 1, isFinal: false), associatedData: [],
			plaintext: [1], nonce: nonce)
		_ = try enc.encryptRandom(
			position: .init(index: 2, isFinal: false), associatedData: [],
			plaintext: [1], nonce: nonce)
		#expect(enc.count(epochIndex: 0) == 2)  // indices 0,1 (>>1 == 0)
		#expect(enc.count(epochIndex: 1) == 1)  // index 2 (>>1 == 1)
	}

	@Test func meteredOutputIsByteIdenticalToStatic() throws {
		// Run an E.15.1-style derived encryption through the encryptor and the raw static.
		let v = try Vectors.load("E15")
		let sched = try Vectors.schedule(from: v)
		let seg = (v["segments"] as! [[String: Any]])[0]
		let pos = SegmentPosition(index: 0, isFinal: false)
		let ctTag = Vectors.ciphertextWithTag(seg)
		let pt = try Segment.decryptDerived(
			schedule: sched, position: pos, associatedData: [], ciphertext: ctTag)
		let enc = PayloadEncryptor(schedule: sched)
		let metered = try enc.encryptDerived(
			position: pos, associatedData: [], plaintext: pt)
		#expect(Hex.encode(metered) == Hex.encode(ctTag))
	}

	@Test func seedResumesCounts() throws {
		let sched = try schedule(aeadID: 0x0002, nonceMode: .random)
		let enc = PayloadEncryptor(schedule: sched)
		enc.seed(epochCounts: [0: 100])
		let nonce = Segment.freshNonce(for: sched.aead)
		_ = try enc.encryptRandom(
			position: .init(index: 0, isFinal: false), associatedData: [],
			plaintext: [1], nonce: nonce)
		#expect(enc.count(epochIndex: 0) == 101)
	}
}
