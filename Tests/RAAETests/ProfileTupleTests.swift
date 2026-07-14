import RAAE
import Testing

/// §4.10.2 Table 13: only certain `(nonce_mode, snap_id)` tuples are valid under each
/// named profile — SEAL-RW-v1 requires the masked multiset hash (random nonce, or
/// derived with an MRAE AEAD); SEAL-RO-v1 pins derived nonce + snap none. An encryptor
/// MUST set a valid tuple and a decryptor MUST reject an invalid one.
@Suite("Profile (nonce_mode, snap_id) tuples (Table 13)")
struct ProfileTupleTests {
	func makeSchedule(
		protocolID: [UInt8], aeadID: UInt16, nonceMode: PayloadInfo.NonceMode,
		snapID: UInt16
	) throws -> PayloadSchedule {
		let info = PayloadInfo(
			aeadID: aeadID, segmentMax: 16384, kdfID: 0x0001, snapID: snapID,
			nonceMode: nonceMode, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: protocolID, cek: [UInt8](repeating: 0xAA, count: 32),
			payloadInfo: info)
	}

	@Test func validTuplesAreAccepted() throws {
		// RW: random + MMH (any AEAD), derived + MMH (MRAE only).
		_ = try makeSchedule(
			protocolID: ProtocolID.mutable, aeadID: 0x0002, nonceMode: .random,
			snapID: SnapID.maskedMultisetHash)
		_ = try makeSchedule(
			protocolID: ProtocolID.mutable, aeadID: 0x001F, nonceMode: .derived,
			snapID: SnapID.maskedMultisetHash)
		// RO: derived + none, any AEAD (write-once keeps each nonce unique).
		_ = try makeSchedule(
			protocolID: ProtocolID.immutable, aeadID: 0x0002, nonceMode: .derived,
			snapID: SnapID.none)
		_ = try makeSchedule(
			protocolID: ProtocolID.immutable, aeadID: 0x001F, nonceMode: .derived,
			snapID: SnapID.none)
	}

	@Test func mutableProfileRequiresSnapshot() {
		// RW + snap none: rewritable objects MUST carry whole-object integrity.
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: .random, snapID: SnapID.none)
		) {
			_ = try makeSchedule(
				protocolID: ProtocolID.mutable, aeadID: 0x0002, nonceMode: .random,
				snapID: SnapID.none)
		}
	}

	@Test func writeOnceProfilePinsDerivedPlusNone() {
		// RO + random nonce is invalid regardless of snap_id.
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: .random, snapID: SnapID.none)
		) {
			_ = try makeSchedule(
				protocolID: ProtocolID.immutable, aeadID: 0x0002,
				nonceMode: .random,
				snapID: SnapID.none)
		}
		// RO + the masked multiset hash is invalid: no snapshot authenticator runs
		// under the immutable profile (the finality bit is the truncation signal).
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: .derived, snapID: SnapID.maskedMultisetHash)
		) {
			_ = try makeSchedule(
				protocolID: ProtocolID.immutable, aeadID: 0x0002,
				nonceMode: .derived,
				snapID: SnapID.maskedMultisetHash)
		}
	}

	@Test func unknownProtocolIDsAreNotTupleConstrained() throws {
		// Custom profiles carry their own rules: the Table-13 tuples do not apply,
		// but the strict MRAE gate for derived mode still does.
		_ = try makeSchedule(
			protocolID: Array("CUSTOM-v1".utf8), aeadID: 0x0002, nonceMode: .random,
			snapID: SnapID.none)
	}
}
