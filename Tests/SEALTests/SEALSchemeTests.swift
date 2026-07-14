import RAAE
import Testing

@testable import SEAL

/// §4.12 Table-15 named-instantiation parameter presets. The spec rows also bind a
/// serialization layout, which the engine does not ship — covered by the doc caveat,
/// asserted here only as parameters.
@Suite("SEAL named-instantiation schemes (Table 15)")
struct SEALSchemeTests {
	@Test func rowParametersMatchTable15() throws {
		let rows: [(SEALScheme, SEALProfile, UInt32, PayloadInfo.NonceMode, UInt8)] = [
			(.attachment, .readOnly, 65536, .derived, 32),
			(.simple, .readWrite, 65536, .random, 16),
			(.memory, .readWrite, 16384, .random, 16),
			(.disk, .readWrite, 16384, .random, 16),
			(.compact, .readWrite, 16384, .derived, 16),
		]
		for (scheme, profile, segmentMax, nonceMode, epoch) in rows {
			// SEAL-compact requires an MRAE AEAD; use GCM-SIV there, GCM elsewhere.
			let aead: UInt16 = scheme == .compact ? 0x001F : 0x0002
			let config = try SEALConfiguration(
				scheme: scheme, aeadID: aead, kdfID: 0x0001)
			#expect(config.profile == profile)
			#expect(config.segmentMax == segmentMax)
			#expect(config.nonceMode == nonceMode)
			#expect(config.epochLength == epoch)
		}
	}

	@Test func rowNonceModeOverridesAEADDefault() throws {
		// SEAL-simple fixes nonce_mode = random even for the MRAE suite, whose
		// per-AEAD default would be derived.
		let config = try SEALConfiguration(scheme: .simple, aeadID: 0x001F, kdfID: 0x0001)
		#expect(config.nonceMode == .random)
	}

	@Test func flatKeyRuleFor256BitNonceSuites() {
		// Table 15: a 256-bit-nonce suite (AEGIS) uses epoch_length 63 regardless of
		// the row. No such suite is registered, so pin the rule via the helper the
		// scheme init routes through.
		for scheme in SEALScheme.allCases {
			#expect(scheme.epochLength(forNonceLength: 32) == 63)
			#expect(scheme.epochLength(forNonceLength: 12) == scheme.epochLength)
		}
	}

	@Test func compactRequiresMRAE() throws {
		#expect(throws: PayloadSchedule.ScheduleError.derivedModeRequiresMRAE(0x0002)) {
			_ = try SEALConfiguration(scheme: .compact, aeadID: 0x0002, kdfID: 0x0001)
		}
		_ = try SEALConfiguration(scheme: .compact, aeadID: 0x001F, kdfID: 0x0001)
	}

	@Test func attachmentSchemeRoundTrips() throws {
		// The write-once attachment configuration end to end, via the preset.
		let config = try SEALConfiguration(
			scheme: .attachment, aeadID: 0x0002, kdfID: 0x0001)
		let cek = SEALConfiguration.generateCEK()
		let writer = try config.startEncryption(cek: cek)
		let segment = try writer.encrypt(
			[9, 8, 7], at: SegmentPosition(index: 0, isFinal: true))
		let object = try writer.finalize()
		#expect(object.snapshot == nil)  // RO: snap_id 0x0000
		let reader = try config.startDecryption(cek: cek, header: object.header)
		#expect(try reader.decrypt(segment) == [9, 8, 7])
	}
}
