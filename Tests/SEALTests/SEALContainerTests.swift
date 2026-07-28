import Foundation
import RAAE
import Testing

@testable import SEAL

/// The reduced immutable linear layout (§4.11.4): byte-exactness against the F.23
/// `SEAL-simple` KAT, the segmentation math, partial fetches, and random access.
@Suite("SEAL immutable container")
struct SEALContainerTests {
	/// `SEAL-simple(AES-256-GCM, HKDF-SHA-256)` — the F.23 instantiation.
	let simple = try! SEALConfiguration(scheme: .simple, aeadID: 0x0002, kdfID: 0x0001)
	/// A small-segment config so multi-segment cases stay byte-cheap.
	let small = try! SEALConfiguration(
		profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 4096,
		epochLength: 32)

	func payload(_ count: Int) -> Data {
		Data((0..<count).map { UInt8($0 % 251) })
	}

	// MARK: F.23 known-answer test

	@Test func f23StoredObjectOpens() throws {
		let v = try Vectors.load("F23")
		let stored = Data(Hex.decode(v["stored_object_hex"] as! String))
		let cek = Data(Hex.decode(v["cek_hex"] as! String))
		let seg = v["segment_0"] as! [String: Any]

		#expect(stored.count == 92)  // 32 salt + 32 commitment + 12 ct + 16 tag
		let plaintext = try simple.open(stored, cek: cek)
		#expect(plaintext.count == 12)

		// Re-encrypting the recovered plaintext under the vector's pinned salt must
		// reproduce the vector's bytes exactly — the encrypt direction of the KAT.
		let resealed = try simple.seal(
			plaintext, cek: cek, globalAssociatedData: Data(),
			salt: Hex.decode(
				(v["payload_info"] as! [String: Any])["salt_hex"] as! String))
		#expect(Hex.encode(Array(resealed)) == (v["stored_object_hex"] as! String))

		// And the vector's own ciphertext/tag are what the object carries.
		let ct =
			Hex.decode(seg["ciphertext_hex"] as! String)
			+ Hex.decode(seg["tag_hex"] as! String)
		#expect(Array(stored.suffix(28)) == ct)
	}

	@Test func f23Geometry() throws {
		let geometry = try simple.linearGeometry(objectByteCount: 92)
		#expect(geometry.segmentCount == 1)
		#expect(geometry.byteRange(ofSegment: 0) == 64..<92)
		#expect(geometry.position(ofSegment: 0) == SegmentPosition(index: 0, isFinal: true))
		#expect(geometry.plaintextByteCount == 12)
		#expect(geometry.byteRange(ofSegment: 1) == nil)
	}

	// MARK: Round trips

	@Test(arguments: [0, 1, 4095, 4096, 8192, 10240])
	func roundTripsAtEveryBoundary(_ length: Int) throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(length)
		let object = try small.seal(original, cek: cek)
		#expect(try small.open(object, cek: cek) == original)

		// An empty payload still carries one authenticated final segment.
		let geometry = try small.linearGeometry(objectByteCount: object.count)
		#expect(geometry.segmentCount == UInt64(max(1, (length + 4095) / 4096)))
		#expect(geometry.plaintextByteCount == length)
	}

	@Test func globalAssociatedDataMustMatch() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let g = Data("attachment-42".utf8)
		let object = try small.seal(payload(100), cek: cek, globalAssociatedData: g)

		#expect(try small.open(object, cek: cek, globalAssociatedData: g).count == 100)
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try small.open(
				object, cek: cek, globalAssociatedData: Data("other".utf8))
		}
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try small.open(object, cek: cek)
		}
	}

	@Test func wrongCEKFailsAtTheCommitment() throws {
		let object = try small.seal(
			payload(50), cek: Data(SEALConfiguration.generateCEK()))
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try small.open(object, cek: Data(SEALConfiguration.generateCEK()))
		}
	}

	// MARK: Header block

	@Test func headerBlockRoundTrips() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let object = try small.seal(payload(10), cek: cek)

		#expect(small.headerByteCount == 64)
		let header = try small.parseHeader(object)  // accepts a whole-object prefix
		#expect(header.encoded == object.prefix(64))
		#expect(try small.parseHeader(header.encoded) == header)

		// A reader built from the header block alone decrypts fetched blocks.
		let reader = try small.startDecryption(cek: cek, headerBlock: header.encoded)
		#expect(
			try reader.decrypt(
				block: Data(object.dropFirst(64)),
				at: SegmentPosition(index: 0, isFinal: true)) == payload(10))

		#expect(throws: SEALError.truncatedHeaderBlock(byteCount: 63, required: 64)) {
			_ = try small.parseHeader(object.prefix(63))
		}
	}

	// MARK: Geometry

	@Test func geometryTilesTheObjectExactly() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let object = try small.seal(payload(10240), cek: cek)  // 2 full + 1 short
		let geometry = try small.linearGeometry(objectByteCount: object.count)

		#expect(geometry.segmentCount == 3)
		#expect(geometry.blockStride == 4096 + 16)
		var offset = geometry.headerByteCount
		for index in 0..<geometry.segmentCount {
			let range = try #require(geometry.byteRange(ofSegment: index))
			#expect(range.lowerBound == offset)
			offset = range.upperBound
		}
		#expect(offset == object.count)
		#expect(geometry.position(ofSegment: 2)?.isFinal == true)
		#expect(geometry.position(ofSegment: 1)?.isFinal == false)
	}

	@Test func geometryRejectsMalformedSizes() throws {
		#expect(throws: SEALError.emptyImmutableObject) {
			_ = try small.linearGeometry(objectByteCount: 64)
		}
		#expect(throws: SEALError.truncatedHeaderBlock(byteCount: 10, required: 64)) {
			_ = try small.linearGeometry(objectByteCount: 10)
		}
		// Trailing bytes shorter than a tag cannot be a segment.
		#expect(throws: SEALError.malformedSegmentation(trailingByteCount: 15)) {
			_ = try small.linearGeometry(objectByteCount: 64 + 4112 + 15)
		}
		let rw = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 4096)
		#expect(throws: SEALError.immutableLayoutRequiresReadOnlyProfile) {
			_ = try rw.linearGeometry(objectByteCount: 4096)
		}
	}

	@Test func plaintextAddressing() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(10240)
		let object = try small.seal(original, cek: cek)
		let geometry = try small.linearGeometry(objectByteCount: object.count)

		#expect(geometry.plaintextByteCount == 10240)
		var covered = 0
		for index in 0..<geometry.segmentCount {
			let range = try #require(geometry.plaintextRange(ofSegment: index))
			#expect(range.lowerBound == covered)
			covered = range.upperBound
			#expect(
				geometry.segmentIndex(containingPlaintextOffset: range.lowerBound)
					== index)
		}
		#expect(covered == 10240)
		#expect(geometry.segmentIndex(containingPlaintextOffset: 10239) == 2)
		#expect(geometry.segmentIndex(containingPlaintextOffset: 10240) == nil)
		#expect(geometry.segmentIndex(containingPlaintextOffset: -1) == nil)

		// Fetch-and-index: read plaintext byte 5000 without opening the whole object.
		let index = try #require(geometry.segmentIndex(containingPlaintextOffset: 5000))
		let byteRange = try #require(geometry.byteRange(ofSegment: index))
		let plaintextRange = try #require(geometry.plaintextRange(ofSegment: index))
		let reader = try small.startDecryption(cek: cek, headerBlock: object)
		let segment = try reader.decrypt(
			block: object[byteRange], at: #require(geometry.position(ofSegment: index)))
		#expect(segment[5000 - plaintextRange.lowerBound] == original[5000])
	}

	// MARK: Random access

	@Test func segmentsOpenIndependentlyAndOnlyAtTheirOwnPosition() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(10240)
		let object = try small.seal(original, cek: cek)
		let geometry = try small.linearGeometry(objectByteCount: object.count)
		let reader = try small.startDecryption(cek: cek, headerBlock: object)

		// Any single interior segment, alone.
		let range = try #require(geometry.byteRange(ofSegment: 1))
		let block = object[range]
		#expect(
			try reader.decrypt(
				block: block, at: #require(geometry.position(ofSegment: 1)))
				== original[4096..<8192])

		// The same block at a wrong index or wrong finality: the derived nonce binds both.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decrypt(
				block: block, at: SegmentPosition(index: 0, isFinal: false))
		}
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decrypt(
				block: block, at: SegmentPosition(index: 1, isFinal: true))
		}
	}

	@Test func fullLengthFinalSegmentIsFinalOnlyUnderIsFinal() throws {
		// An exact multiple of segment_max: the last block is full-width *and* final.
		let cek = Data(SEALConfiguration.generateCEK())
		let object = try small.seal(payload(8192), cek: cek)
		let geometry = try small.linearGeometry(objectByteCount: object.count)
		let reader = try small.startDecryption(cek: cek, headerBlock: object)
		let last = try #require(geometry.byteRange(ofSegment: 1))

		#expect(geometry.finalBlockByteCount == geometry.blockStride)
		#expect(
			try reader.decrypt(
				block: object[last], at: SegmentPosition(index: 1, isFinal: true)
			).count
				== 4096)
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decrypt(
				block: object[last], at: SegmentPosition(index: 1, isFinal: false))
		}
	}

	// MARK: Partial fetches

	@Test func prefixParsingAtEveryCutPoint() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let object = try small.seal(payload(10240), cek: cek)  // 3 segments, short final
		let stride = small.segmentBlockByteCount

		// Header only: nothing to decrypt yet, and no completeness claim to reject.
		let atHeader = try small.parsePrefix(object.prefix(64))
		#expect(atHeader.blocks.isEmpty)
		#expect(atHeader.tail.isEmpty)
		#expect(atHeader.knownInteriorCount == 0)
		#expect(atHeader.resumeOffset == 64)

		// Mid-block: the torn bytes are the tail, and the resume offset skips them.
		let torn = try small.parsePrefix(object.prefix(64 + stride + 100))
		#expect(torn.blocks.count == 1)
		#expect(torn.tail.count == 100)
		#expect(torn.knownInteriorCount == 1)  // block 0 is provably interior
		#expect(torn.resumeOffset == 64 + stride)

		// Exactly on a block boundary: the last block is ambiguous (it could be a
		// full-length final segment), so only earlier blocks are provably interior.
		let onBoundary = try small.parsePrefix(object.prefix(64 + 2 * stride))
		#expect(onBoundary.blocks.count == 2)
		#expect(onBoundary.tail.isEmpty)
		#expect(onBoundary.knownInteriorCount == 1)

		// The whole object: the short tail is the final segment.
		let whole = try small.parsePrefix(object)
		#expect(whole.blocks.count == 2)
		#expect(whole.tail.count == 2048 + 16)
		#expect(whole.knownInteriorCount == 2)
		#expect(whole.resumeOffset == 64 + 2 * stride)

		#expect(throws: SEALError.truncatedHeaderBlock(byteCount: 30, required: 64)) {
			_ = try small.parsePrefix(object.prefix(30))
		}
	}

	@Test func progressiveReadProvesCompletenessOnTheFinalBlock() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(10240)
		let object = try small.seal(original, cek: cek)
		let stride = small.segmentBlockByteCount

		// An interrupted fetch: decrypt what is provably interior, resume, finish.
		let partial = object.prefix(64 + stride + 500)
		let (reader, prefix) = try small.startDecryption(cek: cek, objectPrefix: partial)
		var recovered = Data()
		for k in 0..<prefix.knownInteriorCount {
			recovered += try reader.decrypt(
				block: prefix.blocks[k],
				at: SegmentPosition(index: UInt64(k), isFinal: false))
		}
		#expect(recovered == original.prefix(4096))

		// Mid-transfer the tail is torn — a failed try-final here is expected, not tamper.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try reader.decrypt(
				block: prefix.tail, at: SegmentPosition(index: 1, isFinal: true))
		}

		// Resume from the offset it reported; re-parsing the completed object agrees.
		let resumed =
			partial.prefix(prefix.resumeOffset) + object.dropFirst(prefix.resumeOffset)
		#expect(Data(resumed) == object)

		// Transfer complete: the trailing candidate opens under is_final = 1, which is
		// what proves the object is whole.
		let done = try small.parsePrefix(object)
		for k in 0..<done.knownInteriorCount where k >= prefix.knownInteriorCount {
			recovered += try reader.decrypt(
				block: done.blocks[k],
				at: SegmentPosition(index: UInt64(k), isFinal: false))
		}
		recovered += try reader.decrypt(
			block: done.tail,
			at: SegmentPosition(index: UInt64(done.blocks.count), isFinal: true))
		#expect(recovered == original)
	}

	// MARK: Tamper and truncation

	@Test func truncationAndExtensionFailClosed() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let object = try small.seal(payload(10240), cek: cek)

		// Dropping the final segment: the new last block is interior, so opening it
		// under is_final = 1 fails.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try small.open(
				object.prefix(64 + 2 * small.segmentBlockByteCount), cek: cek)
		}
		// Shaving bytes off the tail: still a well-formed size, fails authentication.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try small.open(object.dropLast(16), cek: cek)
		}
		// Shaving into sub-tag territory: rejected by the segmentation math first.
		#expect(throws: SEALError.malformedSegmentation(trailingByteCount: 15)) {
			_ = try small.open(object.dropLast(2048 + 1), cek: cek)
		}
		// Appending a block: the old final segment is no longer last.
		#expect(throws: AEADError.authenticationFailure) {
			_ = try small.open(object + Data(repeating: 0, count: 4112), cek: cek)
		}
	}

	@Test func reorderedSegmentsFail() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let object = try small.seal(payload(8192), cek: cek)  // 2 full-width blocks
		let stride = small.segmentBlockByteCount
		let swapped =
			object.prefix(64) + object[(64 + stride)...] + object[64..<(64 + stride)]

		#expect(swapped.count == object.count)
		#expect(throws: AEADError.authenticationFailure) {
			_ = try small.open(Data(swapped), cek: cek)
		}
	}

	/// `Data` slices keep their parent's indices, so an object handed over as a slice of
	/// a larger buffer (a framed download, a memory-mapped file) must parse identically.
	@Test func acceptsObjectsPresentedAsNonZeroBasedSlices() throws {
		let cek = Data(SEALConfiguration.generateCEK())
		let original = payload(10240)
		let object = try small.seal(original, cek: cek)
		let framed = Data(repeating: 0xFF, count: 7) + object
		let slice = framed.dropFirst(7)

		#expect(slice.startIndex == 7)
		#expect(try small.open(slice, cek: cek) == original)
		#expect(try small.parseHeader(slice) == small.parseHeader(object))

		let prefix = try small.parsePrefix(slice)
		#expect(prefix.blocks == (try small.parsePrefix(object)).blocks)
		#expect(prefix.tail == (try small.parsePrefix(object)).tail)
	}

	@Test func mutableProfileIsRejectedOnEveryEntryPoint() throws {
		let rw = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 4096)
		let cek = Data(SEALConfiguration.generateCEK())
		#expect(throws: SEALError.immutableLayoutRequiresReadOnlyProfile) {
			_ = try rw.seal(payload(10), cek: cek)
		}
		#expect(throws: SEALError.immutableLayoutRequiresReadOnlyProfile) {
			_ = try rw.open(Data(repeating: 0, count: 200), cek: cek)
		}
		#expect(throws: SEALError.immutableLayoutRequiresReadOnlyProfile) {
			_ = try rw.parsePrefix(Data(repeating: 0, count: 200))
		}
	}
}
