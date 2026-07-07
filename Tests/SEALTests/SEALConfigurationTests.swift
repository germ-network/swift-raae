import RAAE
import Testing

@testable import SEAL

@Suite("SEAL configuration")
struct SEALConfigurationTests {
	@Test func nonceModeAndSnapshotFollowProfile() throws {
		// RO ⇒ derived + snap none, any AEAD (§4.10.2 Table 13).
		let roGCM = try SEALConfiguration(profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001)
		#expect(roGCM.nonceMode == .derived)
		#expect(roGCM.snapID == SnapID.none)
		// RW ⇒ masked multiset hash; nonce mode is the AEAD's Table-9 default.
		let rwGCM = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001)
		#expect(rwGCM.nonceMode == .random)
		#expect(rwGCM.snapID == SnapID.maskedMultisetHash)
		let rwSIV = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x001F, kdfID: 0x0001)
		#expect(rwSIV.nonceMode == .derived)
		#expect(rwSIV.snapID == SnapID.maskedMultisetHash)
	}

	@Test func invalidSuitesAndGeometryAreRejected() {
		#expect(throws: PayloadSchedule.ScheduleError.unsupportedAEAD(0x0021)) {
			_ = try SEALConfiguration(
				profile: .readWrite, aeadID: 0x0021, kdfID: 0x0001)
		}
		#expect(throws: PayloadSchedule.ScheduleError.unsupportedKDF(0x0013)) {
			_ = try SEALConfiguration(
				profile: .readWrite, aeadID: 0x0002, kdfID: 0x0013)
		}
		#expect(throws: PayloadInfo.ValidationError.segmentMaxTooSmall(2048)) {
			_ = try SEALConfiguration(
				profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 2048
			)
		}
		#expect(throws: PayloadInfo.ValidationError.epochLengthOutOfRange(64)) {
			_ = try SEALConfiguration(
				profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, epochLength: 64)
		}
	}

	@Test func generatedCEKsAreFreshAndSized() {
		let a = SEALConfiguration.generateCEK()
		let b = SEALConfiguration.generateCEK()
		#expect(a.count == PayloadSchedule.cekLength)
		#expect(a != b)  // 2^-256 false-failure probability
	}

	@Test func startDecryptionRejectsMismatchedHeader() throws {
		// The reader's expected parameters come from the configuration, not from the
		// (attacker-writable) stored object: any field but the salt differing is a
		// headerMismatch before any KDF work.
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 16384)
		let cek = SEALConfiguration.generateCEK()
		let object = try config.startEncryption(cek: cek).finalize()

		let other = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 65536)
		#expect(throws: SEALError.headerMismatch) {
			_ = try other.startDecryption(cek: cek, header: object.header)
		}
		// The matching configuration accepts it.
		_ = try config.startDecryption(cek: cek, header: object.header)
	}
}
