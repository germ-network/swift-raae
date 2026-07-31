import Foundation
import RAAE
import Testing

@testable import SEAL

/// The self-describing envelope: the pinned prefix encoding, that it leaves the wrapped
/// §4.11.4 object untouched, config-free reading, and the allowlist and tamper
/// behaviour the prefix's lack of authentication depends on.
@Suite("SEAL envelope")
struct SEALEnvelopeTests {
	/// `SEAL-simple(AES-256-GCM, HKDF-SHA-256)` — the F.23 instantiation.
	let simple = try! SEALConfiguration(scheme: .simple, aeadID: 0x0002, kdfID: 0x0001)
	/// The smallest `segment_max` the envelope admits, for cheap multi-segment cases.
	let small = try! SEALConfiguration(
		profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 16384,
		epochLength: 32)

	func payload(_ count: Int) -> Data {
		Data((0..<count).map { UInt8($0 % 251) })
	}

	/// A valid envelope whose prefix has one byte range replaced.
	func retagged(_ envelope: Data, _ range: Range<Int>, _ bytes: [UInt8]) -> Data {
		var copy = envelope
		copy.replaceSubrange(
			(copy.startIndex + range.lowerBound)..<(copy.startIndex + range.upperBound),
			with: bytes)
		return copy
	}

	// MARK: Wire format

	@Test func prefixIsPinned() throws {
		let prefix = try simple.envelopePrefix
		#expect(prefix.count == SEALEnvelope.prefixByteCount)
		#expect(
			Hex.encode(Array(prefix)) == "534541310100000200010001000020",
			"SEA1 | v1 | RO | aead 0x0002 | kdf 0x0001 | segment_max 65536 | epoch 32")

		let parsed = try SEALEnvelope.parse(prefix)
		#expect(parsed.version == SEALEnvelope.currentVersion)
		#expect(parsed.objectOffset == 15)
		#expect(parsed.configuration.aeadID == 0x0002)
		#expect(parsed.configuration.kdfID == 0x0001)
		#expect(parsed.configuration.segmentMax == 65536)
		#expect(parsed.configuration.epochLength == 32)
		#expect(parsed.configuration.profile == .readOnly)
		// Parsing a whole envelope yields the same value as parsing the prefix alone.
		let object = try simple.sealEnvelope(
			payload(10), cek: Data(SEALConfiguration.generateCEK()))
		#expect(try SEALEnvelope.parse(object) == parsed)
	}

	/// The envelope must not disturb the bytes the F.23 KAT pins.
	@Test func wrappedObjectIsTheUnmodifiedF23Object() throws {
		let v = try Vectors.load("F23")
		let stored = Data(Hex.decode(v["stored_object_hex"] as! String))
		let cek = Data(Hex.decode(v["cek_hex"] as! String))
		let salt = Hex.decode((v["payload_info"] as! [String: Any])["salt_hex"] as! String)

		let plaintext = try SEALEnvelope.open(
			try simple.sealEnvelope(
				try simple.open(stored, cek: cek), cek: cek,
				globalAssociatedData: Data(),
				salt: salt),
			cek: cek)
		#expect(plaintext.count == 12)

		let envelope = try simple.sealEnvelope(
			plaintext, cek: cek, globalAssociatedData: Data(), salt: salt)
		#expect(envelope.count == 15 + stored.count)
		#expect(Data(envelope.dropFirst(15)) == stored)
		// The bare reader opens the wrapped object, which is what another
		// implementation will be handed.
		#expect(try simple.open(envelope.dropFirst(15), cek: cek) == plaintext)
	}

	// MARK: Config-free reading

	@Test(
		arguments: [0x0001, 0x0002, 0x001D, 0x001F] as [UInt16],
		[0x0001, 0x0002, 0x0003] as [UInt16])
	func roundTripsWithoutAPriorConfiguration(_ aeadID: UInt16, _ kdfID: UInt16) throws {
		let config = try SEALConfiguration(
			profile: .readOnly, aeadID: aeadID, kdfID: kdfID, segmentMax: 16384,
			epochLength: 32)
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(20000)  // two segments
		let envelope = try config.sealEnvelope(original, cek: cek)

		// No configuration in hand — the prefix supplies it.
		#expect(try SEALEnvelope.open(envelope, cek: cek) == original)

		let parsed = try SEALEnvelope.parse(envelope)
		#expect(parsed.configuration.aeadID == aeadID)
		#expect(parsed.configuration.kdfID == kdfID)
	}

	@Test func globalAssociatedDataStillBinds() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let g = Data("attachment-42".utf8)
		let envelope = try small.sealEnvelope(
			payload(100), cek: cek, globalAssociatedData: g)

		#expect(
			try SEALEnvelope.open(envelope, cek: cek, globalAssociatedData: g).count
				== 100)
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try SEALEnvelope.open(envelope, cek: cek)
		}
	}

	// MARK: Tampering

	/// Every prefix field is commitment-bound, so altering one can never open. Which
	/// check fires varies — `kdf_id` moves the header width and dies while parsing —
	/// so the invariant asserted is the absence of success, not a particular error.
	@Test(
		arguments: [
			(6..<8, [0x00, 0x01] as [UInt8], "aead_id 0x0002 -> 0x0001"),
			(8..<10, [0x00, 0x03], "kdf_id 0x0001 -> 0x0003"),
			(10..<14, [0x00, 0x00, 0x40, 0x00], "segment_max 65536 -> 16384"),
			(14..<15, [31], "epoch_length 32 -> 31"),
		])
	func alteringAnyPrefixFieldFailsBeforeDecryption(
		_ range: Range<Int>, _ bytes: [UInt8], _ label: String
	) throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(200)
		let envelope = try simple.sealEnvelope(original, cek: cek)
		#expect(try SEALEnvelope.open(envelope, cek: cek) == original)

		let tampered = retagged(envelope, range, bytes)
		#expect(tampered != envelope, "\(label): the flip must change the bytes")
		#expect(throws: (any Error).self, "\(label) must not open") {
			_ = try SEALEnvelope.open(tampered, cek: cek)
		}
	}

	// MARK: Allowlist

	@Test func aBareObjectIsNotMistakenForAnEnvelope() throws {
		let bare = try simple.seal(
			payload(10), cek: Data(SEALConfiguration.generateCEK()))
		#expect(throws: SEALError.invalidEnvelopeMagic) {
			_ = try SEALEnvelope.parse(bare)
		}
	}

	@Test func unsupportedPrefixValuesAreNamedNotInferred() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let envelope = try simple.sealEnvelope(payload(10), cek: cek)

		#expect(throws: SEALError.invalidEnvelopeMagic) {
			_ = try SEALEnvelope.parse(retagged(envelope, 0..<4, Array("SEA2".utf8)))
		}
		#expect(throws: SEALError.unsupportedEnvelopeVersion(0x02)) {
			_ = try SEALEnvelope.parse(retagged(envelope, 4..<5, [0x02]))
		}
		// 0x01 is read-write: known, reserved, and not yet serializable.
		#expect(throws: SEALError.unsupportedEnvelopeProfile(0x01)) {
			_ = try SEALEnvelope.parse(retagged(envelope, 5..<6, [0x01]))
		}
		// 4096 satisfies the core's §4.2.1 rule but is not one of SEAL's §4.10 sizes.
		#expect(throws: SEALError.unsupportedEnvelopeSegmentMax(4096)) {
			_ = try SEALEnvelope.parse(
				retagged(envelope, 10..<14, [0x00, 0x00, 0x10, 0x00]))
		}
		#expect(throws: PayloadSchedule.ScheduleError.unsupportedAEAD(0x0021)) {
			_ = try SEALEnvelope.parse(retagged(envelope, 6..<8, [0x00, 0x21]))
		}
		#expect(throws: PayloadSchedule.ScheduleError.unsupportedKDF(0x0013)) {
			_ = try SEALEnvelope.parse(retagged(envelope, 8..<10, [0x00, 0x13]))
		}
		#expect(throws: PayloadInfo.ValidationError.epochLengthOutOfRange(64)) {
			_ = try SEALEnvelope.parse(retagged(envelope, 14..<15, [64]))
		}
		#expect(throws: SEALError.truncatedEnvelope(byteCount: 14, required: 15)) {
			_ = try SEALEnvelope.parse(envelope.prefix(14))
		}
	}

	/// No configuration may produce an envelope its own parser would reject.
	@Test func validationIsSymmetric() throws {
		let tooSmall = try SEALConfiguration(
			profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 4096)
		// The bare container accepts it...
		#expect(
			try tooSmall.open(
				tooSmall.seal(payload(10), cek: Data(repeating: 7, count: 32)),
				cek: Data(repeating: 7, count: 32)) == payload(10))
		// ...the envelope refuses to emit it, matching what parse would refuse to read.
		#expect(throws: SEALError.unsupportedEnvelopeSegmentMax(4096)) {
			_ = try tooSmall.envelopePrefix
		}
		#expect(throws: SEALError.unsupportedEnvelopeSegmentMax(4096)) {
			_ = try tooSmall.sealEnvelope(
				payload(10), cek: Data(SEALConfiguration.generateCEK()))
		}

		let rw = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 16384)
		#expect(throws: SEALError.immutableLayoutRequiresReadOnlyProfile) {
			_ = try rw.envelopePrefix
		}
	}

	// MARK: Geometry

	@Test func geometryRangesAddressTheEnvelope() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(40960)  // 2 full segments + a short one
		let envelope = try small.sealEnvelope(original, cek: cek)
		let parsed = try SEALEnvelope.parse(envelope)
		let geometry = try parsed.geometry(envelopeByteCount: envelope.count)

		#expect(geometry.segmentCount == 3)
		#expect(geometry.baseOffset == 15)
		#expect(geometry.objectByteCount == envelope.count - 15)
		#expect(geometry.plaintextByteCount == 40960)

		// The ranges tile the envelope from the end of the header block to its end.
		var offset = 15 + geometry.headerByteCount
		for index in 0..<geometry.segmentCount {
			let range = try #require(geometry.byteRange(ofSegment: index))
			#expect(range.lowerBound == offset)
			offset = range.upperBound
		}
		#expect(offset == envelope.count)

		// Plaintext addressing is unaffected by the prefix.
		#expect(geometry.plaintextRange(ofSegment: 0) == 0..<16384)
		#expect(geometry.segmentIndex(containingPlaintextOffset: 20000) == 1)

		// Fetch one range straight out of the blob and open it.
		let index = try #require(geometry.segmentIndex(containingPlaintextOffset: 20000))
		let range = try #require(geometry.byteRange(ofSegment: index))
		let plaintextRange = try #require(geometry.plaintextRange(ofSegment: index))
		let reader = try parsed.startDecryption(cek: cek, envelopeBytes: envelope)
		let segment = try reader.decrypt(
			block: envelope[range], at: #require(geometry.position(ofSegment: index)))
		#expect(segment[20000 - plaintextRange.lowerBound] == original[20000])
	}

	@Test func geometriesDifferingOnlyInOffsetAreNotEqual() throws {
		let bare = try small.linearGeometry(objectByteCount: 20000)
		let wrapped = try small.linearGeometry(objectByteCount: 20000, baseOffset: 15)
		#expect(bare != wrapped)
		#expect(bare.byteRange(ofSegment: 0)?.lowerBound == 64)
		#expect(wrapped.byteRange(ofSegment: 0)?.lowerBound == 79)
	}

	@Test func geometryRejectsAnEnvelopeShorterThanItsPrefix() throws {
		let parsed = try SEALEnvelope.parse(try simple.envelopePrefix)
		#expect(throws: SEALError.truncatedEnvelope(byteCount: 10, required: 15)) {
			_ = try parsed.geometry(envelopeByteCount: 10)
		}
		#expect(throws: SEALError.emptyImmutableObject) {
			_ = try parsed.geometry(envelopeByteCount: 15 + 64)
		}
	}

	// MARK: One-shot reader

	@Test func startDecryptionResolvesTheSuiteAndVerifies() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let envelope = try small.sealEnvelope(payload(100), cek: cek)
		// The head alone — prefix plus header block — is enough to build a reader.
		let head = envelope.prefix(15 + 64)

		let (parsed, reader) = try SEALEnvelope.startDecryption(
			cek: cek, envelopeBytes: head)
		#expect(parsed.configuration.segmentMax == 16384)

		let geometry = try parsed.geometry(envelopeByteCount: envelope.count)
		let range = try #require(geometry.byteRange(ofSegment: 0))
		#expect(
			try reader.decrypt(
				block: envelope[range],
				at: #require(geometry.position(ofSegment: 0))) == payload(100))

		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try SEALEnvelope.startDecryption(
				cek: Data(SEALConfiguration.generateCEK()), envelopeBytes: head)
		}
	}

	// MARK: Slice safety

	// MARK: Partial fetches

	@Test func prefixResumeOffsetAddressesTheBlob() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let envelope = try small.sealEnvelope(payload(40960), cek: cek)  // 3 segments
		let parsed = try SEALEnvelope.parse(envelope)
		let base = parsed.objectOffset
		let stride = small.segmentBlockByteCount
		let headerEnd = base + small.headerByteCount

		// Prefix octets are not object bytes: every reported offset clears them.
		let atHeader = try parsed.parsePrefix(envelope.prefix(headerEnd))
		#expect(atHeader.blocks.isEmpty)
		#expect(atHeader.resumeOffset == headerEnd)

		let torn = try parsed.parsePrefix(envelope.prefix(headerEnd + stride + 100))
		#expect(torn.blocks.count == 1)
		#expect(torn.tail.count == 100)
		#expect(torn.knownInteriorCount == 1)
		#expect(torn.resumeOffset == headerEnd + stride)

		// The last whole block stays ambiguous — it may be a full-length final segment.
		let onBoundary = try parsed.parsePrefix(envelope.prefix(headerEnd + 2 * stride))
		#expect(onBoundary.blocks.count == 2)
		#expect(onBoundary.knownInteriorCount == 1)

		// Object-relative parsing of the same cut agrees on every value and differs by
		// exactly the prefix width on the offset — which is the whole point.
		let sameCut = try small.parsePrefix(
			envelope.dropFirst(base).prefix(small.headerByteCount + stride + 100))
		#expect(sameCut.blocks == torn.blocks)
		#expect(sameCut.tail == torn.tail)
		#expect(sameCut.knownInteriorCount == torn.knownInteriorCount)
		#expect(sameCut.resumeOffset == torn.resumeOffset - base)

		#expect(
			throws: SEALError.truncatedEnvelope(
				byteCount: base - 1, required: base)
		) {
			_ = try parsed.parsePrefix(envelope.prefix(base - 1))
		}
	}

	@Test func interruptedEnvelopeFetchResumesAndCompletes() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(40960)
		let envelope = try small.sealEnvelope(original, cek: cek)
		let stride = small.segmentBlockByteCount

		// First chunk: the suite comes off the wire, no configuration in hand.
		let partial = envelope.prefix(SEALEnvelope.prefixByteCount + 64 + stride + 500)
		let (parsed, reader) = try SEALEnvelope.startDecryption(
			cek: cek, envelopeBytes: partial)
		let prefix = try parsed.parsePrefix(partial)

		var recovered = Data()
		for k in 0..<prefix.knownInteriorCount {
			recovered += try reader.decrypt(
				block: prefix.blocks[k],
				at: SegmentPosition(index: UInt64(k), isFinal: false))
		}
		#expect(recovered == original.prefix(16384))

		// Resume the *blob* fetch at the reported offset and stitch: byte-identical to
		// the original envelope. This is the assertion an object-relative offset fails.
		let resumed =
			partial.prefix(prefix.resumeOffset)
			+ envelope.dropFirst(prefix.resumeOffset)
		#expect(Data(resumed) == envelope)

		// Transfer complete: the trailing candidate opens under is_final = 1.
		let done = try parsed.parsePrefix(envelope)
		for k in prefix.knownInteriorCount..<done.knownInteriorCount {
			recovered += try reader.decrypt(
				block: done.blocks[k],
				at: SegmentPosition(index: UInt64(k), isFinal: false))
		}
		recovered += try reader.decrypt(
			block: done.tail,
			at: SegmentPosition(index: UInt64(done.blocks.count), isFinal: true))
		#expect(recovered == original)
	}

	@Test func acceptsNonZeroBasedSlices() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(100)
		let envelope = try small.sealEnvelope(original, cek: cek)

		// A subrange of a larger buffer keeps its parent's indices.
		let padded = Data(repeating: 0xEE, count: 7) + envelope
		let slice = padded[(padded.startIndex + 7)...]
		#expect(slice.startIndex == 7)

		#expect(try SEALEnvelope.parse(slice).objectOffset == 15)
		#expect(try SEALEnvelope.open(slice, cek: cek) == original)
	}
}
