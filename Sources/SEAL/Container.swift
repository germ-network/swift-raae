import Foundation
import RAAE

/// The **reduced immutable linear layout** (§4.11.4) — the one serialization this
/// package ships, and the layout bound to the `SEAL-simple` named instantiation
/// (§4.12, Table 16).
///
/// ```
/// object = salt(32) || commitment(Nh) || (ct_0 || tag_0) || ... || (ct_{n-1} || tag_{n-1})
/// ```
///
/// Nothing else is on the wire: no magic number, no version, no segment count, no
/// length prefixes, no `is_final` flag, and no `payload_info` — the parameters come
/// from the ``SEALConfiguration`` (application context), and version separation is
/// cryptographic (`protocol_id` is a KDF input). Under the immutable profile the
/// per-segment nonce drops out (derived mode, `Np = 0`) and so does the snapshot
/// (`snap_id 0x0000`, `Na = 0`), which is what "reduced" names.
///
/// Segment boundaries are implicit: every non-final ciphertext is exactly
/// `segment_max` octets and only the final one may be shorter (§4.11.1 MUST), so a
/// total byte count determines the segmentation — see ``SEALLinearGeometry``.
///
/// Interfaces here take and return `Foundation.Data`; the engine and core work in
/// `[UInt8]` and conversion happens at this boundary.
extension SealedObjectHeader {
	/// The serialized header block, `salt || commitment` — the fixed-width prefix every
	/// §4.11 layout shares.
	public var encoded: Data { Data(salt) + Data(commitment) }
}

// MARK: - Header block

extension SEALConfiguration {
	/// `32 + commitment_length`: the width of the stored header block.
	public var headerByteCount: Int { 32 + kdf.outputSize }

	/// `segment_max + Nt`: the stride of every non-final segment block.
	///
	/// Clamped rather than trapping on a 32-bit platform, where a `segment_max` above
	/// `Int.max` is unrepresentable — such an object cannot be held in memory there
	/// anyway.
	public var segmentBlockByteCount: Int {
		Int(clamping: UInt64(segmentMax) + UInt64(aead.tagLength))
	}

	/// Parse a stored header block — or any longer prefix that begins with one, such as
	/// a whole object or a partial download.
	///
	/// This reads bytes only; it proves nothing. The commitment is checked when the
	/// header is used to start decryption.
	public func parseHeader(_ bytes: Data) throws -> SealedObjectHeader {
		guard bytes.count >= headerByteCount else {
			throw SEALError.truncatedHeaderBlock(
				byteCount: bytes.count, required: headerByteCount)
		}
		let salt = Array(bytes.prefix(32))
		let commitment = Array(bytes.dropFirst(32).prefix(kdf.outputSize))
		return SealedObjectHeader(
			payloadInfo: payloadInfo(salt: salt), commitment: commitment)
	}

	/// ``startDecryption(cek:header:globalAssociatedData:)`` over a stored header block:
	/// parses it, then verifies the commitment (§4.6) before returning. A wrong CEK,
	/// wrong parameters, wrong `G`, or a corrupted header all fail here.
	public func startDecryption(
		cek: Data, headerBlock: Data, globalAssociatedData: Data = Data()
	) throws -> SEALReader {
		try startDecryption(
			cek: Array(cek), header: parseHeader(headerBlock),
			globalAssociatedData: Array(globalAssociatedData))
	}
}

// MARK: - Geometry

/// The byte↔segment map of a stored object in the reduced immutable linear layout.
///
/// Derived from the object's **total byte count** alone — a `Content-Length` or file
/// size is enough — so a client can compute the byte range of one segment, fetch only
/// that range, and decrypt it without holding the object.
///
/// Index-taking accessors return `nil` for an index at or beyond ``segmentCount``
/// rather than trapping.
public struct SEALLinearGeometry: Equatable, Sendable {
	/// `n_seg`, at least 1 (a zero-segment object is rejected at construction).
	public let segmentCount: UInt64
	public let objectByteCount: Int
	/// Where segment 0's block starts: `32 + commitment_length`.
	public let headerByteCount: Int
	/// `segment_max + Nt` — the width of every block but possibly the last.
	public let blockStride: Int
	/// The last segment's block width, `ct || tag`; equals ``blockStride`` when the
	/// final segment happens to be full-length.
	public let finalBlockByteCount: Int
	let tagLength: Int
	let segmentMaxByteCount: Int

	/// The stored byte range of a segment's block (`ct || tag`), offset from the start
	/// of the object.
	public func byteRange(ofSegment index: UInt64) -> Range<Int>? {
		guard index < segmentCount else { return nil }
		let start = headerByteCount + Int(index) * blockStride
		let width = index == segmentCount - 1 ? finalBlockByteCount : blockStride
		return start..<(start + width)
	}

	/// The segment's position, with `is_final` set on the highest index — the value the
	/// derived nonce binds, so decryption fails if it is wrong.
	public func position(ofSegment index: UInt64) -> SegmentPosition? {
		guard index < segmentCount else { return nil }
		return SegmentPosition(index: index, isFinal: index == segmentCount - 1)
	}

	/// Total plaintext octets across all segments.
	public var plaintextByteCount: Int {
		Int(segmentCount - 1) * segmentMaxByteCount + (finalBlockByteCount - tagLength)
	}

	/// The segment's span within the concatenated plaintext.
	///
	/// - Important: this is the **raw** segment plaintext — the octets the AEAD
	///   returns. An application that frames its own structure inside segments
	///   (headers, padding, records) must map its offsets through that format; this
	///   type knows only the transport layout.
	public func plaintextRange(ofSegment index: UInt64) -> Range<Int>? {
		guard index < segmentCount else { return nil }
		let start = Int(index) * segmentMaxByteCount
		let width =
			index == segmentCount - 1
			? finalBlockByteCount - tagLength : segmentMaxByteCount
		return start..<(start + width)
	}

	/// Which segment holds a given raw-plaintext offset; `nil` past the end.
	public func segmentIndex(containingPlaintextOffset offset: Int) -> UInt64? {
		guard offset >= 0, offset < plaintextByteCount else { return nil }
		return UInt64(offset / segmentMaxByteCount)
	}
}

extension SEALConfiguration {
	/// The segmentation implied by a stored object's total size.
	///
	/// - Throws: ``SEALError/emptyImmutableObject`` for a header with no segments,
	///   ``SEALError/malformedSegmentation(trailingByteCount:)`` when the trailing
	///   bytes are too few to be a segment, ``SEALError/truncatedHeaderBlock(byteCount:required:)``
	///   below header width, and ``SEALError/immutableLayoutRequiresReadOnlyProfile``
	///   on a `SEAL-RW-v1` configuration.
	public func linearGeometry(objectByteCount: Int) throws -> SEALLinearGeometry {
		try requireImmutableProfile()
		guard objectByteCount >= headerByteCount else {
			throw SEALError.truncatedHeaderBlock(
				byteCount: objectByteCount, required: headerByteCount)
		}
		let remainder = objectByteCount - headerByteCount
		guard remainder > 0 else { throw SEALError.emptyImmutableObject }
		let stride = segmentBlockByteCount
		let wholeBlocks = remainder / stride
		let trailing = remainder % stride
		guard trailing == 0 || trailing >= aead.tagLength else {
			throw SEALError.malformedSegmentation(trailingByteCount: trailing)
		}
		return SEALLinearGeometry(
			segmentCount: UInt64(trailing == 0 ? wholeBlocks : wholeBlocks + 1),
			objectByteCount: objectByteCount,
			headerByteCount: headerByteCount,
			blockStride: stride,
			finalBlockByteCount: trailing == 0 ? stride : trailing,
			tagLength: aead.tagLength,
			segmentMaxByteCount: Int(clamping: UInt64(segmentMax)))
	}

	func requireImmutableProfile() throws {
		guard profile == .readOnly else {
			throw SEALError.immutableLayoutRequiresReadOnlyProfile
		}
	}
}

// MARK: - Partial fetches

/// A stored object as far as it has arrived — the shape an interrupted download leaves
/// behind.
///
/// Reading it (see ``SEALConfiguration/parsePrefix(_:)``):
///
/// - `blocks[0..<knownInteriorCount]` are provably interior, because more object
///   follows them. Decrypt those now, at their index, with `is_final = 0`.
/// - The **last** block is ambiguous while `tail` is empty: a final segment may itself
///   be full-length, so it may be segment `n-1` rather than an interior one. Do not
///   decrypt it as interior until more bytes arrive or the transfer ends.
/// - Once the transfer has ended, decrypt the trailing candidate (``tail`` when it is
///   at least `Nt` octets, otherwise the last block) with `is_final = 1`. Success
///   **proves** the object is complete: the derived nonce binds index and finality, so
///   no other block can open that way. Failure *before* the transfer ends is expected
///   (a torn block); failure *after* it ends means truncation or corruption.
public struct SEALLinearPrefix: Equatable, Sendable {
	public let header: SealedObjectHeader
	/// Whole stride-width blocks; `blocks[k]` is segment `k`.
	public let blocks: [Data]
	/// How many leading blocks are provably interior.
	public let knownInteriorCount: Int
	/// Trailing bytes after the last whole block: a torn interior block, or a complete
	/// short final segment. Empty when the prefix ended on a block boundary.
	public let tail: Data
	/// Byte offset to resume the fetch from — the start of the first incomplete block,
	/// so ``tail`` is re-fetched rather than stitched.
	public let resumeOffset: Int
}

extension SEALConfiguration {
	/// Parse however much of a stored object has arrived.
	///
	/// Unlike ``linearGeometry(objectByteCount:)`` this accepts a header with no
	/// segments: a prefix makes no claim of completeness, so there is nothing yet to
	/// reject. Completeness is decided by the trailing-block check described on
	/// ``SEALLinearPrefix``.
	///
	/// - Note: the returned blocks copy the fetched ciphertext. Fine at attachment
	///   scale; a host streaming very large objects should fetch by
	///   ``SEALLinearGeometry/byteRange(ofSegment:)`` instead.
	public func parsePrefix(_ bytes: Data) throws -> SEALLinearPrefix {
		try requireImmutableProfile()
		let header = try parseHeader(bytes)
		let stride = segmentBlockByteCount
		let body = bytes.count - headerByteCount
		let wholeBlocks = body / stride
		var blocks: [Data] = []
		blocks.reserveCapacity(wholeBlocks)
		for k in 0..<wholeBlocks {
			let start = bytes.startIndex + headerByteCount + k * stride
			blocks.append(Data(bytes[start..<(start + stride)]))
		}
		let consumed = headerByteCount + wholeBlocks * stride
		let tail = Data(bytes[(bytes.startIndex + consumed)...])
		return SEALLinearPrefix(
			header: header,
			blocks: blocks,
			knownInteriorCount: tail.isEmpty ? max(blocks.count - 1, 0) : blocks.count,
			tail: tail,
			resumeOffset: consumed)
	}

	/// ``parsePrefix(_:)`` and ``startDecryption(cek:headerBlock:globalAssociatedData:)``
	/// in one step, for a partial download: the commitment is verified once and the
	/// reader opens whichever blocks did arrive.
	public func startDecryption(
		cek: Data, objectPrefix: Data, globalAssociatedData: Data = Data()
	) throws -> (reader: SEALReader, prefix: SEALLinearPrefix) {
		let prefix = try parsePrefix(objectPrefix)
		let reader = try startDecryption(
			cek: Array(cek), header: prefix.header,
			globalAssociatedData: Array(globalAssociatedData))
		return (reader, prefix)
	}
}

// MARK: - Random-access decryption

extension SEALReader {
	/// Decrypt one stored segment block (`ct || tag`) at a known position — the
	/// random-access entry point.
	///
	/// Segments open in any order and independently; a block presented at the wrong
	/// index or with the wrong finality fails authentication, because the derived nonce
	/// binds both.
	///
	/// - Important: opening interior segments proves each one authentic, not that the
	///   object is whole. Under `SEAL-RO-v1` there is no snapshot, so completeness rests
	///   on the final segment opening with `is_final = 1` (§4.10.2).
	public func decrypt(
		block: Data, at position: SegmentPosition, associatedData: Data = Data()
	) throws -> Data {
		try configuration.requireImmutableProfile()
		let segment = SealedSegment(
			position: position, nonce: nil, ciphertext: Array(block))
		return Data(try decrypt(segment, associatedData: Array(associatedData)))
	}
}

// MARK: - Whole-object convenience

extension SEALConfiguration {
	/// Seal a whole payload into one stored object (§4.11.4).
	///
	/// The payload is split into `segment_max`-octet segments, the last carrying
	/// `is_final = 1`. An empty payload still produces one (empty) final segment: its
	/// tag authenticates the emptiness, where a segment-less object could not be told
	/// apart from one whose segments were deleted.
	///
	/// - Parameter globalAssociatedData: the raAE `G` (§4.6) — bound into the
	///   commitment, never stored, re-supplied on open.
	public func seal(
		_ plaintext: Data, cek: Data, globalAssociatedData: Data = Data()
	) throws -> Data {
		try seal(
			plaintext, cek: cek, globalAssociatedData: globalAssociatedData, salt: nil)
	}

	/// Vector seam: the same object under a pinned salt, so a KAT can compare bytes.
	func seal(
		_ plaintext: Data, cek: Data, globalAssociatedData: Data, salt: [UInt8]?
	) throws -> Data {
		try requireImmutableProfile()
		let writer = try SEALWriter(
			configuration: self, cek: Array(cek),
			globalAssociatedData: Array(globalAssociatedData), advantageLog2: 32,
			salt: salt)
		let bytes = Array(plaintext)
		let chunk = Int(clamping: UInt64(segmentMax))
		let segmentCount = bytes.isEmpty ? 1 : (bytes.count + chunk - 1) / chunk
		var object = writer.header.encoded
		for index in 0..<segmentCount {
			let start = index * chunk
			let end = min(start + chunk, bytes.count)
			let segment = try writer.encrypt(
				Array(bytes[start..<end]),
				at: SegmentPosition(
					index: UInt64(index), isFinal: index == segmentCount - 1))
			object += Data(segment.ciphertext)
		}
		// Runs the engine's finality-shape check; an immutable object has no snapshot.
		_ = try writer.finalize()
		return object
	}

	/// Open a whole stored object: verify the commitment, then decrypt every segment in
	/// order and return the concatenated payload.
	///
	/// The final segment is opened with `is_final = 1`, so truncation and extension
	/// fail authentication here (§4.9.1.2, Appendix E). To read part of a large object
	/// instead, use ``linearGeometry(objectByteCount:)`` with
	/// ``SEALReader/decrypt(block:at:associatedData:)``.
	public func open(
		_ storedObject: Data, cek: Data, globalAssociatedData: Data = Data()
	) throws -> Data {
		let geometry = try linearGeometry(objectByteCount: storedObject.count)
		let reader = try startDecryption(
			cek: cek, headerBlock: storedObject,
			globalAssociatedData: globalAssociatedData)
		var plaintext = Data()
		for index in 0..<geometry.segmentCount {
			guard let range = geometry.byteRange(ofSegment: index),
				let position = geometry.position(ofSegment: index)
			else { throw SEALError.malformedSegmentation(trailingByteCount: 0) }
			let start = storedObject.startIndex + range.lowerBound
			let block = Data(storedObject[start..<(start + range.count)])
			plaintext += try reader.decrypt(block: block, at: position)
		}
		return plaintext
	}
}
