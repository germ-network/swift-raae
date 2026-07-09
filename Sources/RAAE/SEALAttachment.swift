import Foundation

/// The `SEAL-attachment(aead_id, kdf_id)` named instantiation (draft §4.12) — SEAL's
/// write-once random-access preset, and the scheme `draft-sullivan-mls-attachments`
/// uses for MLS attachment encryption.
///
/// The instantiation fixes everything but the cipher suite: the write-once
/// `SEAL-RO-v1` profile, derived nonce mode, `segment_max` 65536 (64 KiB),
/// `epoch_length` 32, no snapshot authenticator (`snap_id` 0x0000),
/// `commitment_length = Nh`, and a fresh 32-octet salt per object. The AEAD and KDF
/// are the referencing protocol's choice — for MLS, the IANA code points of the
/// group's cipher suite (``Suite/init(mlsCipherSuite:)``).
///
/// The object is the linear layout in its reduced immutable form (§4.11.4): a header
/// followed by back-to-back segments, with no stored nonces (derived mode) and no
/// stored snapshot. Every non-final segment holds exactly ``segmentSize`` plaintext
/// octets, only the final segment may be shorter, and a valid object has at least one
/// segment (an empty attachment is a single tag-only final segment):
///
/// ```
/// object    = salt(32) || commitment(Nh) || segment(0) || ... || segment(n-1)
/// segment   = ciphertext || tag(16)
/// offset(i) = (32 + Nh) + i * (65536 + 16)
/// ```
///
/// The attachment's `object_id` is bound as SEAL's global associated data `G`
/// (attachments draft §5.2), so a wrong or missing `object_id` fails the commitment
/// check exactly like a wrong CEK, and both sides pass an empty per-segment `A_i`.
/// The 32-octet CEK arrives from the MLS side (`SafeExportSecret` →
/// `ExpandWithLabel(component_secret, ..., object_id, 32)`, attachments draft §4.1);
/// this layer never derives or transports it.
///
/// Encryption is metered: the write-once discipline (§4.5.3.2) is exactly one
/// encryption per segment index, which ``Writer`` enforces through
/// ``PayloadEncryptor`` (a rewrite hard-stops — with a non-MRAE AEAD it would reuse
/// the segment's fixed derived nonce). The salt-uniqueness obligation is the
/// encryptor's (attachments draft §7.3): never re-encrypt under a previously used
/// `(object_id, salt)` pair, including after a crash or retry — ``startEncrypt``
/// generates a fresh random salt by default.
public enum SEALAttachment {
	/// `segment_size` — plaintext octets per non-final segment (§4.12 Table 15).
	public static let segmentSize = 65536
	/// AEAD tag length. Every admitted suite (AES-GCM, ChaCha20-Poly1305) has `Nt = 16`.
	public static let tagLength = 16
	/// Per-object salt length (§4.9.1.1).
	public static let saltLength = 32
	/// `epoch_length` — write-once content performs no rewrites, so the instantiation
	/// takes a large epoch: one epoch key covers 2^32 segment indices (§4.12).
	public static let epochLength: UInt8 = 32
	/// The attachments draft bounds `object_id` at 255 octets and forbids empty (§4.2);
	/// a receiver MUST reject an empty `object_id` (§5.2).
	public static let maxObjectIDLength = 255

	/// Failures specific to the attachment framing; schedule and segment failures
	/// propagate as ``PayloadSchedule/ScheduleError``,
	/// ``PayloadSchedule/CommitmentError``, ``Segment/SegmentError``, ``BudgetError``,
	/// and ``AEADError``.
	public enum AttachmentError: Error, Equatable {
		/// `object_id` was empty or longer than ``maxObjectIDLength`` octets
		/// (attachments draft §4.2 / §5.2).
		case invalidObjectIDLength(Int)
		/// The header was not exactly `32 + Nh` octets for the suite's KDF.
		case headerLengthMismatch(expected: Int, got: Int)
		/// The object cannot hold the header plus one (tag-only) segment.
		case objectTooShort(length: Int, minimum: Int)
		/// The object's final segment is shorter than the AEAD tag.
		case invalidFinalSegmentLength(Int)
		/// A non-final segment's plaintext was not exactly ``segmentSize`` octets, or
		/// a final segment's exceeded it — the linear layout's computable offsets
		/// (§4.11.4) hold only when every non-final segment is full.
		case invalidSegmentPlaintextLength(length: Int, isFinal: Bool)
	}

	/// The cipher suite: SEAL's `aead_id`/`kdf_id` code points (Tables 7–8), which for
	/// MLS are the IANA registrations of the group's cipher suite's AEAD (RFC 5116) and
	/// KDF (RFC 9180) — the attachments draft §5.
	public struct Suite: Equatable, Sendable {
		public let aeadID: UInt16
		public let kdfID: UInt16

		public init(aeadID: UInt16, kdfID: UInt16) {
			self.aeadID = aeadID
			self.kdfID = kdfID
		}

		/// Map an MLS cipher suite (RFC 9420 §17.1) to its AEAD/KDF code points, or
		/// `nil` for an unknown suite value.
		public init?(mlsCipherSuite: UInt16) {
			// (aead, kdf): AES-128-GCM 0x0001, AES-256-GCM 0x0002,
			// ChaCha20-Poly1305 0x001D; HKDF-SHA-256/384/512 0x0001/0x0002/0x0003.
			switch mlsCipherSuite {
			case 0x0001, 0x0002:  // MLS_128_*_AES128GCM_SHA256_*
				self.init(aeadID: 0x0001, kdfID: 0x0001)
			case 0x0003:  // MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
				self.init(aeadID: 0x001D, kdfID: 0x0001)
			case 0x0004, 0x0005:  // MLS_256_*_AES256GCM_SHA512_*
				self.init(aeadID: 0x0002, kdfID: 0x0003)
			case 0x0006:  // MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
				self.init(aeadID: 0x001D, kdfID: 0x0003)
			case 0x0007:  // MLS_256_DHKEMP384_AES256GCM_SHA384_P384
				self.init(aeadID: 0x0002, kdfID: 0x0002)
			default:
				return nil
			}
		}
	}

	/// Byte geometry of one object under a suite: where the header ends and each
	/// segment starts (§4.11.4 / attachments draft §5.1). Offsets and lengths are
	/// `Int`; objects beyond `Int.max` octets are not addressable on the platform.
	public struct Layout: Equatable, Sendable {
		/// `Nh` — the commitment's length in the header.
		public let commitmentLength: Int

		/// `32 + Nh`.
		public var headerLength: Int { saltLength + commitmentLength }
		/// One stored segment: `segment_size + Nt` = 65552.
		public var segmentStride: Int { segmentSize + tagLength }

		/// `offset(i) = (32 + Nh) + i * (65536 + 16)`.
		public func segmentOffset(_ index: Int) -> Int {
			headerLength + index * segmentStride
		}

		/// The segment covering a plaintext offset.
		public func segmentIndex(forPlaintextOffset offset: Int) -> Int {
			offset / segmentSize
		}

		/// Segments in an object of `plaintextLength` octets: `ceil(len / 65536)`,
		/// minimum 1 (an empty attachment is one empty final segment).
		public func segmentCount(plaintextLength: Int) -> Int {
			plaintextLength == 0
				? 1 : (plaintextLength + segmentSize - 1) / segmentSize
		}

		/// Total encrypted object length: header plus one tag per segment plus the
		/// plaintext.
		public func objectLength(plaintextLength: Int) -> Int {
			headerLength + segmentCount(plaintextLength: plaintextLength) * tagLength
				+ plaintextLength
		}
	}

	/// The layout for a suite (`Nh` comes from its KDF). Throws
	/// ``PayloadSchedule/ScheduleError/unsupportedKDF(_:)`` for an unknown `kdf_id`.
	public static func layout(suite: Suite) throws -> Layout {
		guard let kdf = SuiteRegistry.kdf(id: suite.kdfID) else {
			throw PayloadSchedule.ScheduleError.unsupportedKDF(suite.kdfID)
		}
		return Layout(commitmentLength: kdf.outputSize)
	}

	/// The instantiation's `payload_info` for a suite and per-object salt (§4.12
	/// Table 15). Exposed for interop testing; ``startEncrypt(cek:objectID:suite:salt:)``
	/// and ``startDecrypt(cek:objectID:suite:header:)`` build it internally.
	public static func payloadInfo(suite: Suite, salt: [UInt8]) -> PayloadInfo {
		PayloadInfo(
			aeadID: suite.aeadID, segmentMax: UInt32(segmentSize), kdfID: suite.kdfID,
			snapID: SnapID.none, nonceMode: .derived, epochLength: epochLength,
			salt: salt)
	}

	/// A fresh uniformly random 32-octet per-object salt (attachments draft §7.3).
	public static func freshSalt() -> [UInt8] {
		var salt = [UInt8](repeating: 0, count: saltLength)
		for i in salt.indices {
			salt[i] = UInt8.random(in: 0...255)
		}
		return salt
	}

	/// Encrypt-side state from ``startEncrypt(cek:objectID:suite:salt:)``: the header
	/// to store at offset 0 and the metered segment encryptor. A mutable reference
	/// type (the meter is stateful) and not `Sendable`; one writer per object.
	public final class Writer {
		/// `salt || commitment` — the object's first `32 + Nh` octets.
		public let header: [UInt8]
		public let layout: Layout
		/// The underlying meter, exposed for counter persistence across a resume
		/// (``PayloadEncryptor/persistableState``); encrypt through
		/// ``encryptSegment(index:isFinal:plaintext:)``, which enforces the layout.
		public let encryptor: PayloadEncryptor

		public var schedule: PayloadSchedule { encryptor.schedule }

		init(header: [UInt8], layout: Layout, encryptor: PayloadEncryptor) {
			self.header = header
			self.layout = layout
			self.encryptor = encryptor
		}

		/// `EncSeg`: encrypt the segment at `index`, returning `ciphertext || tag` to
		/// store at `layout.segmentOffset(index)`. The per-segment associated data is
		/// empty per the attachments draft (§5.2). A non-final plaintext must be
		/// exactly ``segmentSize`` octets (the layout's offsets depend on it); a
		/// second encryption at the same index throws
		/// ``BudgetError/segmentRewriteBudgetExceeded(index:count:limitLog2:)`` —
		/// write-once means exactly one encryption per segment.
		public func encryptSegment(
			index: UInt64, isFinal: Bool, plaintext: [UInt8]
		) throws -> [UInt8] {
			let valid =
				isFinal
				? plaintext.count <= segmentSize : plaintext.count == segmentSize
			guard valid else {
				throw AttachmentError.invalidSegmentPlaintextLength(
					length: plaintext.count, isFinal: isFinal)
			}
			return try encryptor.encryptDerived(
				position: SegmentPosition(index: index, isFinal: isFinal),
				associatedData: [], plaintext: plaintext)
		}
	}

	/// Decrypt-side state from ``startDecrypt(cek:objectID:suite:header:)``: a
	/// commitment-verified schedule plus the layout. The header is not needed again —
	/// fetch and open any segment by its computed offset.
	public struct Reader {
		public let schedule: PayloadSchedule
		public let layout: Layout

		/// `DecSeg`: open the stored segment (`ciphertext || tag`) at `index`. The
		/// AEAD authenticates the contents, the index, and the finality bit through
		/// the derived nonce; the per-segment associated data is empty per the
		/// attachments draft (§5.2). Throws ``AEADError/authenticationFailure`` on
		/// any mismatch.
		public func decryptSegment(
			index: UInt64, isFinal: Bool, segment: [UInt8]
		) throws -> [UInt8] {
			try Segment.decryptDerived(
				schedule: schedule,
				position: SegmentPosition(index: index, isFinal: isFinal),
				associatedData: [], ciphertext: segment)
		}
	}

	/// raAE `StartEnc` for one attachment object: derive the schedule from the CEK
	/// with `G = object_id`, and return the ``Writer`` holding the header
	/// (`salt || commitment`) and the metered encryptor.
	///
	/// - Parameter salt: pass `nil` (the default) for a fresh random salt — required
	///   for production use (attachments draft §7.3); an explicit salt is for test
	///   vectors and interop reproduction only.
	public static func startEncrypt(
		cek: [UInt8], objectID: [UInt8], suite: Suite, salt: [UInt8]? = nil
	) throws -> Writer {
		try validateObjectID(objectID)
		let salt = salt ?? freshSalt()
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.immutable, cek: cek,
			payloadInfo: payloadInfo(suite: suite, salt: salt), globalAAD: objectID)
		return Writer(
			header: salt + schedule.commitment,
			layout: Layout(commitmentLength: schedule.commitment.count),
			encryptor: PayloadEncryptor(schedule: schedule))
	}

	/// raAE `StartDec` for one attachment object: split the header into salt and
	/// commitment, re-derive the schedule with `G = object_id`, and verify the
	/// commitment **before** returning a ``Reader`` — a wrong CEK, suite, or
	/// `object_id` is rejected here, before any segment is fetched (attachments
	/// draft §5.2).
	public static func startDecrypt(
		cek: [UInt8], objectID: [UInt8], suite: Suite, header: [UInt8]
	) throws -> Reader {
		try validateObjectID(objectID)
		let layout = try Self.layout(suite: suite)
		guard header.count == layout.headerLength else {
			throw AttachmentError.headerLengthMismatch(
				expected: layout.headerLength, got: header.count)
		}
		let schedule = try PayloadSchedule.startDecrypt(
			protocolID: ProtocolID.immutable, cek: cek,
			payloadInfo: payloadInfo(
				suite: suite, salt: Array(header[..<saltLength])),
			globalAAD: objectID,
			publishedCommitment: Array(header[saltLength...]),
			expectedCommitmentLength: layout.commitmentLength)
		return Reader(schedule: schedule, layout: layout)
	}

	/// One-shot encryption: the complete object bytes (header followed by every
	/// segment) for a whole plaintext. Suits attachment-sized payloads held in
	/// memory; for streaming, drive a ``Writer`` segment by segment.
	public static func encrypt(
		cek: [UInt8], objectID: [UInt8], suite: Suite, plaintext: [UInt8],
		salt: [UInt8]? = nil
	) throws -> [UInt8] {
		let writer = try startEncrypt(
			cek: cek, objectID: objectID, suite: suite, salt: salt)
		let count = writer.layout.segmentCount(plaintextLength: plaintext.count)
		var object = writer.header
		object.reserveCapacity(
			writer.layout.objectLength(plaintextLength: plaintext.count))
		for i in 0..<count {
			let lo = i * segmentSize
			let hi = min(lo + segmentSize, plaintext.count)
			object += try writer.encryptSegment(
				index: UInt64(i), isFinal: i == count - 1,
				plaintext: Array(plaintext[lo..<hi]))
		}
		return object
	}

	/// One-shot decryption of a complete object: verifies the commitment, then opens
	/// every segment in order (index `n-1` as final), so the whole-object integrity
	/// check of the attachments draft (§5.2) — truncation, extension, reordering,
	/// substitution — is carried by the per-segment failures. For random access,
	/// use ``startDecrypt(cek:objectID:suite:header:)`` and fetch segments by offset.
	public static func decrypt(
		cek: [UInt8], objectID: [UInt8], suite: Suite, object: [UInt8]
	) throws -> [UInt8] {
		let layout = try Self.layout(suite: suite)
		// At least one (possibly tag-only) segment after the header.
		let minimum = layout.headerLength + tagLength
		guard object.count >= minimum else {
			throw AttachmentError.objectTooShort(
				length: object.count, minimum: minimum)
		}
		let reader = try startDecrypt(
			cek: cek, objectID: objectID, suite: suite,
			header: Array(object[..<layout.headerLength]))
		let body = object.count - layout.headerLength
		let count = (body + layout.segmentStride - 1) / layout.segmentStride
		let finalLength = body - (count - 1) * layout.segmentStride
		guard finalLength >= tagLength else {
			throw AttachmentError.invalidFinalSegmentLength(finalLength)
		}
		var plaintext: [UInt8] = []
		plaintext.reserveCapacity(body - count * tagLength)
		for i in 0..<count {
			let lo = layout.segmentOffset(i)
			let hi = i == count - 1 ? object.count : lo + layout.segmentStride
			plaintext += try reader.decryptSegment(
				index: UInt64(i), isFinal: i == count - 1,
				segment: Array(object[lo..<hi]))
		}
		return plaintext
	}

	/// Attachments draft §4.2 / §5.2: `object_id` is non-empty and at most 255 octets.
	static func validateObjectID(_ objectID: [UInt8]) throws {
		guard !objectID.isEmpty, objectID.count <= maxObjectIDLength else {
			throw AttachmentError.invalidObjectIDLength(objectID.count)
		}
	}
}
