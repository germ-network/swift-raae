import RAAE
import Testing

/// `snap_id` validation: unknown Table-12 code points are rejected in
/// `PayloadSchedule.init`, mirroring the strict handling of unknown
/// `aead_id`/`kdf_id`. The field is committed into the KDF, so silently accepting an
/// unknown value would bind parameters this build cannot honor. The -02 registry
/// defines 0x0002 (digest transcript) and 0x0003 (epoch digest tree); this build does
/// not implement them, so they are rejected the same way.
@Suite("snap_id validation")
struct SnapIDValidationTests {
	/// A schedule with the given snap_id on its profile's valid tuple (§4.10.2):
	/// `SEAL-RW-v1` for the masked multiset hash, `SEAL-RO-v1` (derived) for none.
	func makeSchedule(snapID: UInt16) throws -> PayloadSchedule {
		let isNone = snapID == SnapID.none
		let info = PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: snapID,
			nonceMode: isNone ? .derived : .random, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: isNone ? ProtocolID.immutable : ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: info)
	}

	@Test func knownSnapIDsAreAccepted() throws {
		// 0x0000 none (write-once profile), 0x0001 masked multiset hash (mutable).
		_ = try makeSchedule(snapID: SnapID.none)
		_ = try makeSchedule(snapID: SnapID.maskedMultisetHash)
		#expect(SuiteRegistry.isKnownSnapID(SnapID.none))
		#expect(SuiteRegistry.isKnownSnapID(SnapID.maskedMultisetHash))
	}

	@Test func unknownSnapIDsAreRejected() {
		// 0x0002/0x0003 are -02-defined but unimplemented; they fail as unsupported
		// (registry check) before any profile-tuple consideration.
		for id in [UInt16(0x0002), 0x0003, 0x7777, 0xFFFF] {
			#expect(!SuiteRegistry.isKnownSnapID(id))
			#expect(throws: PayloadSchedule.ScheduleError.unsupportedSnapID(id)) {
				_ = try makeSchedule(snapID: id)
			}
		}
	}
}

/// §4.10.2 Table 14: only certain `(nonce_mode, snap_id)` tuples are valid under each
/// named profile — an encryptor MUST NOT emit an off-table tuple and a decryptor MUST
/// reject one. Of this build's authenticators: `SEAL-RW-v1` ⇒ the masked multiset
/// hash; `SEAL-RO-v1` ⇒ derived nonce + no authenticator. Unknown protocol IDs define
/// their own tuples and are unconstrained (only the §4.5.3.2 MRAE gate applies).
@Suite("Profile tuple validation (§4.10.2)")
struct ProfileTupleTests {
	func info(snapID: UInt16, nonceMode: PayloadInfo.NonceMode) -> PayloadInfo {
		PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: snapID,
			nonceMode: nonceMode, epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
	}
	let cek = [UInt8](repeating: 0xAA, count: 32)

	@Test func mutableRequiresSnapshotAuthenticator() {
		// SEAL-RW-v1 + snap_id 0x0000: every rewritable object must carry
		// whole-object integrity.
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: 0, snapID: 0x0000)
		) {
			_ = try PayloadSchedule(
				protocolID: ProtocolID.mutable, cek: cek,
				payloadInfo: info(snapID: SnapID.none, nonceMode: .random))
		}
	}

	@Test func writeOnceRejectsSnapshotAuthenticator() {
		// SEAL-RO-v1 + snap_id 0x0001: the profile's tuple is (derived, 0x0000).
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: 1, snapID: 0x0001)
		) {
			_ = try PayloadSchedule(
				protocolID: ProtocolID.immutable, cek: cek,
				payloadInfo: info(
					snapID: SnapID.maskedMultisetHash, nonceMode: .derived))
		}
	}

	@Test func writeOnceRejectsRandomNonceMode() {
		// SEAL-RO-v1 selects a derived nonce (§4.10.2); random is off-profile.
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: 0, snapID: 0x0000)
		) {
			_ = try PayloadSchedule(
				protocolID: ProtocolID.immutable, cek: cek,
				payloadInfo: info(snapID: SnapID.none, nonceMode: .random))
		}
	}

	@Test func startDecryptRejectsOffProfileTuple() throws {
		// The decrypt-side MUST (§4.10.2) flows through startDecrypt, which uses the
		// same initializer: an off-profile object is rejected before any commitment
		// comparison, regardless of the published value.
		#expect(
			throws: PayloadSchedule.ScheduleError.invalidProfileTuple(
				nonceMode: 0, snapID: 0x0000)
		) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek,
				payloadInfo: info(snapID: SnapID.none, nonceMode: .random),
				publishedCommitment: [UInt8](repeating: 0, count: 32))
		}
	}

	@Test func unknownProtocolIDCarriesNoTupleConstraint() throws {
		// A custom profile defines its own tuples: both combinations that the named
		// profiles reject construct fine (random mode dodges the MRAE gate too).
		let custom = Array("CUSTOM-v1".utf8)
		_ = try PayloadSchedule(
			protocolID: custom, cek: cek,
			payloadInfo: info(snapID: SnapID.none, nonceMode: .random))
		_ = try PayloadSchedule(
			protocolID: custom, cek: cek,
			payloadInfo: info(snapID: SnapID.maskedMultisetHash, nonceMode: .random))
	}
}
