import Testing

@testable import RAAE

/// The §4.5.3.2 write-once relaxation: derived nonce mode with a non-MRAE AEAD is
/// permitted under the `SEAL-RO-v1` profile only — each segment is encrypted exactly
/// once, so its fixed derived nonce is never reused. Any other protocol ID (including
/// unknown ones) keeps the strict MRAE gate.
@Suite("Write-once profile (SEAL-RO-v1)")
struct WriteOnceProfileTests {
	func makeSchedule(
		protocolID: [UInt8], aeadID: UInt16, epochLength: UInt8 = 0
	) throws -> PayloadSchedule {
		let info = PayloadInfo(
			aeadID: aeadID, segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: .derived, epochLength: epochLength,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: protocolID, cek: [UInt8](repeating: 0xAA, count: 32),
			payloadInfo: info)
	}

	@Test func derivedNonMRAEAllowedUnderWriteOnce() throws {
		// AES-256-GCM (0x0002) and ChaCha20-Poly1305 (0x001D) are non-MRAE; §4.5.3.2
		// confines them to a write-once profile in derived mode — SEAL-RO-v1 qualifies.
		for id in [UInt16(0x0002), 0x001D] {
			let schedule = try makeSchedule(
				protocolID: ProtocolID.immutable, aeadID: id)
			#expect(schedule.isWriteOnceProfile)
		}
		// The mutable profile is not write-once (its derived mode still requires MRAE;
		// see SecurityHardeningTests.derivedModeWithNonMRAEIsRejected).
		let mutableSIV = try makeSchedule(protocolID: ProtocolID.mutable, aeadID: 0x001F)
		#expect(!mutableSIV.isWriteOnceProfile)
	}

	@Test func unknownProtocolIDStaysStrict() {
		// An unrecognized protocol ID carries no write-once guarantee, so the strict
		// gate applies: the draft imposes no obligations on custom profiles, and a
		// rewrite under a reused derived nonce would be catastrophic for GCM.
		#expect(throws: PayloadSchedule.ScheduleError.derivedModeRequiresMRAE(0x0002)) {
			_ = try makeSchedule(protocolID: Bytes.ascii("CUSTOM-v1"), aeadID: 0x0002)
		}
	}

	@Test func writeOnceDerivedRoundTrip() throws {
		// Multi-segment encrypt/decrypt in the write-once attachment configuration:
		// SEAL-RO-v1, derived nonces, AES-256-GCM. Encryption goes through the metered
		// PayloadEncryptor — the unmetered Segment static refuses this pairing (see
		// rawStaticRefusesUnmeteredWriteOnceEncryption).
		let schedule = try makeSchedule(protocolID: ProtocolID.immutable, aeadID: 0x0002)
		let encryptor = PayloadEncryptor(schedule: schedule)
		let plaintexts: [[UInt8]] = [[1, 2, 3], [4, 5], [6]]
		var ciphertexts: [[UInt8]] = []
		for (i, pt) in plaintexts.enumerated() {
			let pos = SegmentPosition(
				index: UInt64(i), isFinal: i == plaintexts.count - 1)
			ciphertexts.append(
				try encryptor.encryptDerived(
					position: pos, associatedData: [], plaintext: pt))
		}
		for (i, ct) in ciphertexts.enumerated() {
			let pos = SegmentPosition(
				index: UInt64(i), isFinal: i == plaintexts.count - 1)
			let back = try Segment.decryptDerived(
				schedule: schedule, position: pos, associatedData: [],
				ciphertext: ct)
			#expect(back == plaintexts[i])
		}
		// A segment presented at the wrong position must fail authentication:
		// index and finality are bound through the derived nonce.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try Segment.decryptDerived(
				schedule: schedule,
				position: SegmentPosition(index: 1, isFinal: false),
				associatedData: [], ciphertext: ciphertexts[0])
		}
	}

	@Test func rawStaticRefusesUnmeteredWriteOnceEncryption() throws {
		// §4.5.3.2 licenses derived + non-MRAE only under a one-encryption-per-segment
		// discipline; the unmetered static cannot uphold it, so it refuses and steers
		// to PayloadEncryptor. Decryption is unaffected (no nonce-reuse hazard).
		let schedule = try makeSchedule(protocolID: ProtocolID.immutable, aeadID: 0x0002)
		#expect(throws: Segment.SegmentError.writeOnceRequiresMeteredEncryptor) {
			_ = try Segment.encryptDerived(
				schedule: schedule,
				position: SegmentPosition(index: 0, isFinal: true),
				associatedData: [], plaintext: [1, 2, 3])
		}
		// An MRAE AEAD stays available unmetered, write-once or not: the synthetic IV
		// bounds nonce reuse, so the pairing never depends on the metered discipline.
		let siv = try makeSchedule(protocolID: ProtocolID.immutable, aeadID: 0x001F)
		_ = try Segment.encryptDerived(
			schedule: siv, position: SegmentPosition(index: 0, isFinal: true),
			associatedData: [], plaintext: [1, 2, 3])
	}

	@Test func writeOnceRewriteHardStopsEvenUnderWarn() throws {
		// The write-once per-segment cap is not a soft budget: exceeding it reuses the
		// segment's fixed nonce under GCM. `.warn` must not let it through.
		let schedule = try makeSchedule(protocolID: ProtocolID.immutable, aeadID: 0x0002)
		let encryptor = PayloadEncryptor(schedule: schedule, policy: .warn)
		var events: [BudgetEvent] = []
		encryptor.onBudgetEvent = { events.append($0) }
		let pos = SegmentPosition(index: 0, isFinal: false)
		_ = try encryptor.encryptDerived(position: pos, associatedData: [], plaintext: [1])
		#expect(
			throws: BudgetError.segmentRewriteBudgetExceeded(
				index: 0, count: 2, limitLog2: 0)
		) {
			_ = try encryptor.encryptDerived(
				position: pos, associatedData: [], plaintext: [1])
		}
		// The event still fired (both policies report), the counter did not advance,
		// and a first write of a fresh index still succeeds.
		#expect(events.contains { $0.kind == .segment })
		#expect(encryptor.segmentRewriteCounts[0] == 1)
		_ = try encryptor.encryptDerived(
			position: SegmentPosition(index: 1, isFinal: true), associatedData: [],
			plaintext: [2])
	}

	/// KAT pinning the SEAL-RO-v1 schedule bytes (CEK 32×0xAA, salt 32×0x04,
	/// AES-256-GCM, HKDF-SHA-256, derived mode, epoch_length 0). The secret keys were
	/// generated with an independent implementation of the draft's labeled-KDF
	/// construction (§4.3/§4.5), itself verified byte-exact against Appendix E.1 —
	/// this guards the profile-string plumbing: SEAL-RO-v1 derivations differ from
	/// the vendored RW vectors only through `protocol_id`. The commitment reflects the
	/// draft-sullivan-cfrg-raae-01 always-framed-empty-G convention (§4.5.1; the
	/// independent generator predated it) — the secret keys never take `G`, so they are
	/// unchanged by the resync.
	@Test func writeOnceScheduleKAT() throws {
		let schedule = try makeSchedule(protocolID: ProtocolID.immutable, aeadID: 0x0002)
		#expect(
			Hex.encode(schedule.commitment)
				== "71e7b3c7b33b73a45e77492c45cd3dccbe3eda769dbce5f3455d0ebc8bbe3004"
		)
		#expect(
			keyHex(schedule.payloadKey)
				== "ac89c67fb105c26268b86c3d6c32af4078ff07cae372e67cc745a66eb244dbc7"
		)
		#expect(
			keyHex(schedule.snapKey)
				== "ab5071a5264b3c5ab5016a659ce35e848c2982ea18662090613fcd1b9de3ca0e"
		)
		#expect(schedule.nonceBase != nil)
		#expect(keyHex(schedule.nonceBase!) == "e9b82704e941ef3b55b2ad7b")
		// epoch_length 0 ⇒ segment_key(i) = epoch_key(i), distinct per segment.
		#expect(
			keyHex(schedule.segmentKey(index: 0))
				== "99f0bf82058a0728da317a2d2b4bbb9f3b7d9c613c38f7f7186bd2edb36f200a"
		)
		#expect(
			keyHex(schedule.segmentKey(index: 1))
				== "018d3521b09160467e208bcd326fa9c882003bff3af773f863a65fa5d4510a87"
		)
		let base = keyBytes(schedule.nonceBase!)
		#expect(
			Hex.encode(
				try Segment.derivedNonce(
					nonceBase: base, position: .init(index: 0, isFinal: false)))
				== "e9b82704e941ef3b55b2ad7b")
		#expect(
			Hex.encode(
				try Segment.derivedNonce(
					nonceBase: base, position: .init(index: 1, isFinal: true)))
				== "e9b82704e941ef3b55b2ad78")
	}
}
