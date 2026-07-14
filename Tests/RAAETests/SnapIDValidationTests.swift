import RAAE
import Testing

/// `snap_id` validation: unsupported code points (draft-02 Table 12) are rejected in
/// `PayloadSchedule.init`, mirroring the strict handling of unknown
/// `aead_id`/`kdf_id`. The field is committed into the KDF, so silently accepting an
/// unsupported value would bind parameters this build cannot honor.
@Suite("snap_id validation")
struct SnapIDValidationTests {
	func makeSchedule(snapID: UInt16) throws -> PayloadSchedule {
		let info = PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: snapID,
			nonceMode: .random, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: info)
	}

	@Test func knownSnapIDsAreAccepted() throws {
		// 0x0000 none, 0x0001 masked multiset hash (Table 12). Each is accepted
		// under the profile whose §4.10.2 tuple admits it: MMH under SEAL-RW-v1,
		// none under SEAL-RO-v1 (derived nonce; ProfileTupleTests covers the
		// cross-pairings).
		_ = try makeSchedule(snapID: SnapID.maskedMultisetHash)
		let roInfo = PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: SnapID.none,
			nonceMode: .derived, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		_ = try PayloadSchedule(
			protocolID: ProtocolID.immutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: roInfo)
		#expect(SuiteRegistry.isKnownSnapID(SnapID.none))
		#expect(SuiteRegistry.isKnownSnapID(SnapID.maskedMultisetHash))
	}

	@Test func unknownSnapIDsAreRejected() {
		// Unassigned code points (0x0004 and up) are unknown.
		for id in [UInt16(0x0004), 0x7777, 0xFFFF] {
			#expect(!SuiteRegistry.isKnownSnapID(id))
			#expect(throws: PayloadSchedule.ScheduleError.unsupportedSnapID(id)) {
				_ = try makeSchedule(snapID: id)
			}
		}
	}

	@Test func draft02UnimplementedSnapIDsAreRejected() {
		// draft-02 defines 0x0002 (digest transcript) and 0x0003 (epoch digest tree);
		// this build implements neither, so both are rejected as unsupported — not
		// silently accepted as valid parameters.
		for id in [UInt16(0x0002), 0x0003] {
			#expect(!SuiteRegistry.isKnownSnapID(id))
			#expect(throws: PayloadSchedule.ScheduleError.unsupportedSnapID(id)) {
				_ = try makeSchedule(snapID: id)
			}
		}
	}
}
