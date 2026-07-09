import Testing

@testable import RAAE

/// The `SEAL-attachment(aead_id, kdf_id)` named instantiation (§4.12) as consumed by
/// draft-sullivan-mls-attachments: write-once `SEAL-RO-v1`, derived nonces, 65536-octet
/// segments, `epoch_length` 32, `snap_id` 0x0000, header `salt(32) || commitment(Nh)`,
/// linear segments at `offset(i) = (32+Nh) + i·(65536+16)`, and `G = object_id`.
@Suite("SEAL-attachment preset (MLS attachments)")
struct SEALAttachmentTests {
	let cek = [UInt8](repeating: 0xAA, count: 32)
	let salt = [UInt8](repeating: 0x04, count: 32)
	let objectID = Bytes.ascii("test-attachment-object-id")
	/// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 → AES-128-GCM + HKDF-SHA-256.
	let suite128 = SEALAttachment.Suite(mlsCipherSuite: 0x0001)!

	@Test func mlsCipherSuiteMapping() {
		// RFC 9420 §17.1 → (RFC 5116 aead_id, RFC 9180 kdf_id).
		let expected: [UInt16: (aead: UInt16, kdf: UInt16)] = [
			0x0001: (0x0001, 0x0001), 0x0002: (0x0001, 0x0001),
			0x0003: (0x001D, 0x0001), 0x0004: (0x0002, 0x0003),
			0x0005: (0x0002, 0x0003), 0x0006: (0x001D, 0x0003),
			0x0007: (0x0002, 0x0002),
		]
		for (id, pair) in expected {
			let suite = SEALAttachment.Suite(mlsCipherSuite: id)
			#expect(suite?.aeadID == pair.aead, "suite \(id)")
			#expect(suite?.kdfID == pair.kdf, "suite \(id)")
		}
		#expect(SEALAttachment.Suite(mlsCipherSuite: 0x0000) == nil)
		#expect(SEALAttachment.Suite(mlsCipherSuite: 0x0008) == nil)
	}

	@Test func presetPayloadInfoShape() throws {
		// §4.12 Table 15: SEAL-RO-v1, 65536, derived, epoch 32, snap 0x0000.
		let info = SEALAttachment.payloadInfo(suite: suite128, salt: salt)
		#expect(info.aeadID == 0x0001)
		#expect(info.segmentMax == 65536)
		#expect(info.kdfID == 0x0001)
		#expect(info.snapID == SnapID.none)
		#expect(info.nonceMode == .derived)
		#expect(info.epochLength == 32)
		try info.validate()
		let writer = try SEALAttachment.startEncrypt(
			cek: cek, objectID: objectID, suite: suite128, salt: salt)
		#expect(writer.schedule.isWriteOnceProfile)
		#expect(writer.schedule.protocolID == ProtocolID.immutable)
	}

	@Test func layoutOffsets() throws {
		// offset(i) = (32 + Nh) + i * (65536 + 16), attachments draft §5.1.
		let layout = try SEALAttachment.layout(suite: suite128)
		#expect(layout.headerLength == 64)  // Nh = 32
		#expect(layout.segmentStride == 65552)
		#expect(layout.segmentOffset(0) == 64)
		#expect(layout.segmentOffset(3) == 64 + 3 * 65552)
		#expect(layout.segmentIndex(forPlaintextOffset: 65535) == 0)
		#expect(layout.segmentIndex(forPlaintextOffset: 65536) == 1)
		// Per-suite Nh: SHA-384 → 80-octet header, SHA-512 → 96.
		#expect(
			try SEALAttachment.layout(
				suite: SEALAttachment.Suite(mlsCipherSuite: 0x0007)!
			).headerLength == 80)
		#expect(
			try SEALAttachment.layout(
				suite: SEALAttachment.Suite(mlsCipherSuite: 0x0004)!
			).headerLength == 96)
		#expect(throws: PayloadSchedule.ScheduleError.unsupportedKDF(0x7777)) {
			_ = try SEALAttachment.layout(
				suite: SEALAttachment.Suite(aeadID: 0x0001, kdfID: 0x7777))
		}

		// Segment counts and object length: an empty attachment is one tag-only
		// final segment; a boundary-length plaintext has a full final segment.
		#expect(layout.segmentCount(plaintextLength: 0) == 1)
		#expect(layout.segmentCount(plaintextLength: 1) == 1)
		#expect(layout.segmentCount(plaintextLength: 65536) == 1)
		#expect(layout.segmentCount(plaintextLength: 65537) == 2)
		#expect(layout.segmentCount(plaintextLength: 131072) == 2)
		#expect(layout.objectLength(plaintextLength: 0) == 64 + 16)
		#expect(layout.objectLength(plaintextLength: 65537) == 64 + 2 * 16 + 65537)
	}

	/// KAT pinning the SEAL-attachment schedule (CEK 32×0xAA, salt 32×0x04,
	/// object_id "test-attachment-object-id", AES-128-GCM + HKDF-SHA-256). Expected
	/// values were generated with an independent implementation of the draft's
	/// labeled-KDF construction (§4.3/§4.5), itself verified byte-exact against
	/// Appendix E.1/E.2 — this pins the preset's parameter plumbing (profile string,
	/// epoch 32, snap 0x0000, derived mode, G element) end to end.
	@Test func attachmentScheduleKAT() throws {
		let writer = try SEALAttachment.startEncrypt(
			cek: cek, objectID: objectID, suite: suite128, salt: salt)
		let schedule = writer.schedule
		#expect(
			Hex.encode(schedule.commitment)
				== "5d2e1a1336eac1a385a14c77ac90b34890ff547af8f0ec968bd5f034a509634f"
		)
		#expect(writer.header == salt + schedule.commitment)
		#expect(keyHex(schedule.payloadKey) == "f89db5220c711b10449aad14b2a92526")
		#expect(
			keyHex(schedule.snapKey)
				== "bf8c57791ad063ef855b10775edf4c70b265916378c32cabe9caa2d4940fb986"
		)
		#expect(keyHex(schedule.nonceBase!) == "6a6e28f2de6f541440fe07d4")
		// epoch_length 32: indices 0 and 1 share epoch key 0; index 2^32 starts epoch 1.
		#expect(keyHex(schedule.segmentKey(index: 0)) == "5a1913e6553ccde374b18611a9f75416")
		#expect(
			keyHex(schedule.segmentKey(index: 1))
				== keyHex(schedule.segmentKey(index: 0)))
		#expect(
			keyHex(schedule.segmentKey(index: UInt64(1) << 32))
				== "204fbd45b0ae77a631c0fd698e188d8b")
		let base = keyBytes(schedule.nonceBase!)
		#expect(
			Hex.encode(
				try Segment.derivedNonce(
					nonceBase: base, position: .init(index: 0, isFinal: true)))
				== "6a6e28f2de6f541440fe07d5")
		#expect(
			Hex.encode(
				try Segment.derivedNonce(
					nonceBase: base, position: .init(index: 1, isFinal: false)))
				== "6a6e28f2de6f541440fe07d6")
		// The SHA-384 suite derives a 48-octet (Nh) commitment.
		let suite384 = SEALAttachment.Suite(mlsCipherSuite: 0x0007)!
		let writer384 = try SEALAttachment.startEncrypt(
			cek: cek, objectID: objectID, suite: suite384, salt: salt)
		#expect(
			Hex.encode(writer384.schedule.commitment)
				== "691e3df69f5d22e95997660a7c98b7dbbf61d79b8f78f8d814b25556d567ff0e13d31898849bebbdc869346e3262a76a"
		)
	}

	@Test func oneShotRoundTripAcrossSegmentBoundaries() throws {
		let layout = try SEALAttachment.layout(suite: suite128)
		for length in [0, 1, 65535, 65536, 65537, 131_072, 131_079] {
			let plaintext = (0..<length).map { UInt8(truncatingIfNeeded: $0) }
			let object = try SEALAttachment.encrypt(
				cek: cek, objectID: objectID, suite: suite128, plaintext: plaintext)
			#expect(object.count == layout.objectLength(plaintextLength: length))
			let back = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite128, object: object)
			#expect(back == plaintext, "length \(length)")
		}
	}

	@Test func crossSuiteRoundTrip() throws {
		// Every RFC 9420 cipher suite (AES-128/256-GCM, ChaCha20-Poly1305 ×
		// HKDF-SHA-256/384/512) round-trips a two-segment attachment.
		let plaintext = (0..<65537).map { UInt8(truncatingIfNeeded: $0) }
		for mlsID in UInt16(0x0001)...0x0007 {
			let suite = SEALAttachment.Suite(mlsCipherSuite: mlsID)!
			let object = try SEALAttachment.encrypt(
				cek: cek, objectID: objectID, suite: suite, plaintext: plaintext)
			let back = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite, object: object)
			#expect(back == plaintext, "MLS suite \(mlsID)")
		}
	}

	@Test func randomAccessSegmentRead() throws {
		// The attachments draft §5.2 read path: initialize from the header once,
		// then fetch and open only the segments covering the requested range.
		let plaintext = (0..<140_000).map { UInt8(truncatingIfNeeded: $0) }
		let object = try SEALAttachment.encrypt(
			cek: cek, objectID: objectID, suite: suite128, plaintext: plaintext,
			salt: salt)
		let layout = try SEALAttachment.layout(suite: suite128)
		let reader = try SEALAttachment.startDecrypt(
			cek: cek, objectID: objectID, suite: suite128,
			header: Array(object[..<layout.headerLength]))
		// Segment 1 (of 0, 1, 2) alone: fetch its stride, open at its index.
		let lo = layout.segmentOffset(1)
		let segment = Array(object[lo..<(lo + layout.segmentStride)])
		let back = try reader.decryptSegment(index: 1, isFinal: false, segment: segment)
		#expect(back == Array(plaintext[65536..<131_072]))
		// The same bytes at the wrong index or finality fail authentication.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decryptSegment(index: 0, isFinal: false, segment: segment)
		}
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decryptSegment(index: 1, isFinal: true, segment: segment)
		}
	}

	@Test func wrongObjectIDFailsCommitment() throws {
		// G = object_id: a wrong or missing object_id fails StartDec exactly like a
		// wrong CEK (attachments draft §5.2).
		let object = try SEALAttachment.encrypt(
			cek: cek, objectID: objectID, suite: suite128, plaintext: [1, 2, 3])
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try SEALAttachment.decrypt(
				cek: cek, objectID: Bytes.ascii("other-object-id"),
				suite: suite128, object: object)
		}
		var wrongCEK = cek
		wrongCEK[0] ^= 0x01
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try SEALAttachment.decrypt(
				cek: wrongCEK, objectID: objectID, suite: suite128, object: object)
		}
	}

	@Test func tamperedObjectFails() throws {
		let plaintext = (0..<70_000).map { UInt8(truncatingIfNeeded: $0) }
		let object = try SEALAttachment.encrypt(
			cek: cek, objectID: objectID, suite: suite128, plaintext: plaintext)
		let layout = try SEALAttachment.layout(suite: suite128)

		// A flipped salt octet re-derives a different schedule; a flipped
		// commitment octet fails the constant-time compare.
		for index in [0, layout.headerLength - 1] {
			var tampered = object
			tampered[index] ^= 0x01
			#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
				_ = try SEALAttachment.decrypt(
					cek: cek, objectID: objectID, suite: suite128,
					object: tampered)
			}
		}
		// A flipped segment octet fails that segment's AEAD open.
		var tampered = object
		tampered[layout.segmentOffset(1) + 5] ^= 0x01
		#expect(throws: AEADError.authenticationFailure) {
			_ = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite128, object: tampered)
		}
	}

	@Test func truncationAndFramingRejected() throws {
		let plaintext = (0..<70_000).map { UInt8(truncatingIfNeeded: $0) }
		let object = try SEALAttachment.encrypt(
			cek: cek, objectID: objectID, suite: suite128, plaintext: plaintext)
		let layout = try SEALAttachment.layout(suite: suite128)

		// Dropping the final segment leaves the (non-final) segment 0 presented as
		// final — the finality bit is bound through the derived nonce.
		let dropped = Array(object[..<layout.segmentOffset(1)])
		#expect(throws: AEADError.authenticationFailure) {
			_ = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite128, object: dropped)
		}
		// Truncating into the final tag leaves a sub-tag remainder.
		let intoTag = Array(object[..<(layout.segmentOffset(1) + 8)])
		#expect(throws: SEALAttachment.AttachmentError.invalidFinalSegmentLength(8)) {
			_ = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite128, object: intoTag)
		}
		// Truncating a mid-segment ciphertext octet shifts the framing.
		let midCut = Array(object[..<(object.count - 1)])
		#expect(throws: AEADError.authenticationFailure) {
			_ = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite128, object: midCut)
		}
		// Shorter than header + one tag-only segment.
		#expect(
			throws: SEALAttachment.AttachmentError.objectTooShort(
				length: layout.headerLength, minimum: layout.headerLength + 16)
		) {
			_ = try SEALAttachment.decrypt(
				cek: cek, objectID: objectID, suite: suite128,
				object: Array(object[..<layout.headerLength]))
		}
		// A header of the wrong length is rejected before any derivation.
		#expect(
			throws: SEALAttachment.AttachmentError.headerLengthMismatch(
				expected: layout.headerLength, got: layout.headerLength - 1)
		) {
			_ = try SEALAttachment.startDecrypt(
				cek: cek, objectID: objectID, suite: suite128,
				header: Array(object[..<(layout.headerLength - 1)]))
		}
	}

	@Test func objectIDBoundsEnforced() throws {
		// Non-empty and at most 255 octets (attachments draft §4.2 / §5.2), checked
		// on both sides.
		#expect(throws: SEALAttachment.AttachmentError.invalidObjectIDLength(0)) {
			_ = try SEALAttachment.startEncrypt(cek: cek, objectID: [], suite: suite128)
		}
		let oversize = [UInt8](repeating: 0x41, count: 256)
		#expect(throws: SEALAttachment.AttachmentError.invalidObjectIDLength(256)) {
			_ = try SEALAttachment.startEncrypt(
				cek: cek, objectID: oversize, suite: suite128)
		}
		#expect(throws: SEALAttachment.AttachmentError.invalidObjectIDLength(0)) {
			_ = try SEALAttachment.startDecrypt(
				cek: cek, objectID: [], suite: suite128,
				header: [UInt8](repeating: 0, count: 64))
		}
		// The 255-octet maximum itself is accepted.
		let atMax = [UInt8](repeating: 0x41, count: 255)
		_ = try SEALAttachment.startEncrypt(cek: cek, objectID: atMax, suite: suite128)
	}

	@Test func writerEnforcesWriteOnceAndLayout() throws {
		let writer = try SEALAttachment.startEncrypt(
			cek: cek, objectID: objectID, suite: suite128)
		// Non-final segments must be exactly segment_size (computable offsets).
		#expect(
			throws: SEALAttachment.AttachmentError.invalidSegmentPlaintextLength(
				length: 3, isFinal: false)
		) {
			_ = try writer.encryptSegment(
				index: 0, isFinal: false, plaintext: [1, 2, 3])
		}
		// A final segment beyond segment_size is likewise malformed.
		#expect(
			throws: SEALAttachment.AttachmentError.invalidSegmentPlaintextLength(
				length: 65537, isFinal: true)
		) {
			_ = try writer.encryptSegment(
				index: 0, isFinal: true,
				plaintext: [UInt8](repeating: 0, count: 65537))
		}
		// Write-once: a second encryption at the same index hard-stops — it would
		// reuse the segment's fixed derived nonce under AES-GCM (§4.5.3.2).
		_ = try writer.encryptSegment(index: 0, isFinal: true, plaintext: [1, 2, 3])
		#expect(
			throws: BudgetError.segmentRewriteBudgetExceeded(
				index: 0, count: 2, limitLog2: 0)
		) {
			_ = try writer.encryptSegment(
				index: 0, isFinal: true, plaintext: [1, 2, 3])
		}
	}

	@Test func freshSaltIsGeneratedPerObject() throws {
		// Defaulted salt: fresh per startEncrypt (attachments draft §7.3), 32 octets,
		// and carried verbatim in the header.
		let a = try SEALAttachment.startEncrypt(
			cek: cek, objectID: objectID, suite: suite128)
		let b = try SEALAttachment.startEncrypt(
			cek: cek, objectID: objectID, suite: suite128)
		#expect(Array(a.header[..<32]) != Array(b.header[..<32]))
		#expect(a.header.count == 64)
		#expect(a.schedule.payloadInfo.salt == Array(a.header[..<32]))
	}
}
