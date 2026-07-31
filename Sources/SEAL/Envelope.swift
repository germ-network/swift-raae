import Foundation
import RAAE

/// A self-describing wrapper that carries the cipher suite alongside a stored object.
///
/// ```
/// envelope = magic(4) || version(1) || profile(1) || aead_id(2) || kdf_id(2)
///            || segment_max(4) || epoch_length(1) || object
/// ```
///
/// > Important: this framing is **ours, not the draft's**. The wrapped `object` is an
/// > unmodified reduced immutable linear layout (§4.11.4) — drop ``objectOffset``
/// > octets and what remains is byte-identical to what
/// > ``SEALConfiguration/seal(_:cek:globalAssociatedData:)`` produces, and is what a
/// > conforming implementation of another language will read. The draft delegates this
/// > layer to the consuming protocol (§4.11.2 reserves "an arbitrary-length prefix …
/// > which raAE does not specify"), so nothing here is claimed as spec conformance.
///
/// Without it, a stored object is not self-describing: `kdf_id` fixes `Nh`, which fixes
/// the header width, so a reader must already know the suite to find the first segment
/// boundary. Every blob is then coupled to a hardcoded ``SEALConfiguration``, and a
/// parameter mismatch surfaces only as a commitment failure — which per §6.3 says
/// *that* something disagrees, never *which* field.
///
/// ## Security properties
///
/// The prefix is **unauthenticated but commitment-bound**. Every field it carries feeds
/// key derivation — the four suite fields through `payload_info`, the profile through
/// `protocol_id` — so altering any of them fails the commitment (§4.6) before a single
/// AEAD operation runs. Substituting `aead_id` 0x0002 for 0x0001 does not downgrade the
/// cipher; it produces a rejection. Which check fires varies by field (changing
/// `kdf_id` moves the header width, so that one is caught while parsing), and the
/// invariant to rely on is that no alteration yields a successful open.
///
/// Per §6.3 a consuming protocol must still reject unrecognized parameters *before*
/// decryption rather than inferring them from a commitment failure, so parsing
/// allowlists every field and reports the offending one by name.
///
/// The suite is visible to anyone holding the bytes. `payload_info` is public by design
/// and the suite is largely inferable from object length and context regardless, but
/// the envelope makes it explicit rather than implicit.
///
/// Values derived from a parsed prefix — everything ``geometry(envelopeByteCount:)`` and
/// ``parsePrefix(_:)`` return — describe what the bytes *claim*, and claim nothing until
/// ``startDecryption(cek:envelopeBytes:globalAssociatedData:)`` checks the commitment. A
/// caller sizing a buffer from ``SEALLinearGeometry/plaintextByteCount`` before that
/// check is sizing it from attacker-influenced input. The allowlist bounds the damage —
/// `segment_max` is one of two values, so the figure cannot be inflated more than
/// fourfold, and every block still has to authenticate — but the ordering is worth
/// keeping straight.
///
/// ## Scope
///
/// Read-only in v1: the wrapped layout is the immutable one, and the profile octet is
/// reserved so a future read-write layout — which needs stored nonces and a snapshot,
/// a different geometry — can claim `0x01`.
public struct SEALEnvelope: Sendable {
	/// ASCII `"SEA1"`. A bare object opens with a random salt, so without a magic number
	/// the allowlist alone would be separating the two formats probabilistically — every
	/// field would have to land outside its accepted set for a bare object to be
	/// rejected. Four octets make the discrimination deterministic for a host holding
	/// both enveloped and bare blobs.
	public static let magic: [UInt8] = Array("SEA1".utf8)
	public static let currentVersion: UInt8 = 0x01
	/// Width of the prefix in ``currentVersion``; see ``objectOffset`` for the value
	/// that survives a version change.
	public static let prefixByteCount = 15
	/// `segment_max` values SEAL defines (§4.10). Narrower than the core's power-of-two
	/// ≥ 4096 rule (§4.2.1) — see ``SEALConfiguration/envelopePrefix``.
	public static let supportedSegmentMaxValues: Set<UInt32> = [16384, 65536]

	/// The only profile octet v1 accepts; `0x01` is reserved for a read-write layout.
	static let profileReadOnly: UInt8 = 0x00

	public let version: UInt8
	/// The suite the prefix declared, validated at parse.
	public let configuration: SEALConfiguration
	/// Where the wrapped object begins. Equals ``prefixByteCount`` under
	/// ``currentVersion``; read it rather than the constant so callers keep working if
	/// a later version changes the prefix width.
	public let objectOffset: Int
}

// `SEALConfiguration` holds `AEAD`/`KeyDerivation` existentials and is not `Equatable`,
// so this compares the wire fields it was parsed from.
extension SEALEnvelope: Equatable {
	public static func == (lhs: SEALEnvelope, rhs: SEALEnvelope) -> Bool {
		lhs.version == rhs.version
			&& lhs.objectOffset == rhs.objectOffset
			&& lhs.configuration.profile == rhs.configuration.profile
			&& lhs.configuration.aeadID == rhs.configuration.aeadID
			&& lhs.configuration.kdfID == rhs.configuration.kdfID
			&& lhs.configuration.segmentMax == rhs.configuration.segmentMax
			&& lhs.configuration.epochLength == rhs.configuration.epochLength
	}
}

// MARK: - Writing

extension SEALConfiguration {
	/// This configuration encoded as an envelope prefix.
	///
	/// - Throws: ``SEALError/immutableLayoutRequiresReadOnlyProfile`` on a `SEAL-RW-v1`
	///   configuration, and ``SEALError/unsupportedEnvelopeSegmentMax(_:)`` for a
	///   `segment_max` outside ``SEALEnvelope/supportedSegmentMaxValues``.
	///
	/// The `segment_max` check is deliberately stricter than
	/// ``SEALConfiguration/init(profile:aeadID:kdfID:segmentMax:epochLength:)``, which
	/// takes the parameterized construction's power-of-two ≥ 4096 (§4.2.1) while §4.10
	/// gives SEAL only 16384 and 65536. Applying it here as well as at parse keeps the
	/// two directions symmetric: no configuration can produce an envelope that its own
	/// parser would reject. Bare ``seal(_:cek:globalAssociatedData:)`` is unaffected and
	/// keeps the looser rule.
	public var envelopePrefix: Data {
		get throws {
			try requireImmutableProfile()
			guard SEALEnvelope.supportedSegmentMaxValues.contains(segmentMax) else {
				throw SEALError.unsupportedEnvelopeSegmentMax(segmentMax)
			}
			var prefix = Data(SEALEnvelope.magic)
			prefix.append(SEALEnvelope.currentVersion)
			prefix.append(SEALEnvelope.profileReadOnly)
			prefix.append(contentsOf: bigEndian(aeadID))
			prefix.append(contentsOf: bigEndian(kdfID))
			prefix.append(contentsOf: bigEndian(segmentMax))
			prefix.append(epochLength)
			return prefix
		}
	}

	/// Seal a whole payload into a self-describing envelope: ``envelopePrefix`` followed
	/// by the object ``seal(_:cek:globalAssociatedData:)`` produces.
	public func sealEnvelope(
		_ plaintext: Data, cek: Data, globalAssociatedData: Data = Data()
	) throws -> Data {
		try sealEnvelope(
			plaintext, cek: cek, globalAssociatedData: globalAssociatedData, salt: nil)
	}

	/// Vector seam: the same envelope under a pinned salt, so a KAT can compare bytes.
	func sealEnvelope(
		_ plaintext: Data, cek: Data, globalAssociatedData: Data, salt: [UInt8]?
	) throws -> Data {
		try envelopePrefix
			+ seal(
				plaintext, cek: cek, globalAssociatedData: globalAssociatedData,
				salt: salt)
	}
}

// MARK: - Reading

extension SEALEnvelope {
	/// Parse a prefix — or any longer run of bytes beginning with one, such as a whole
	/// envelope or a partial download.
	///
	/// This reads and allowlists bytes; it proves nothing. The declared parameters are
	/// checked against the commitment when the envelope is used to start decryption.
	///
	/// - Throws: ``SEALError/truncatedEnvelope(byteCount:required:)``,
	///   ``SEALError/invalidEnvelopeMagic``,
	///   ``SEALError/unsupportedEnvelopeVersion(_:)``,
	///   ``SEALError/unsupportedEnvelopeProfile(_:)``,
	///   ``SEALError/unsupportedEnvelopeSegmentMax(_:)``, and the core's
	///   `unsupportedAEAD` / `unsupportedKDF` / `epochLengthOutOfRange` for the
	///   remaining fields — each naming the field that failed.
	public static func parse(_ bytes: Data) throws -> SEALEnvelope {
		guard bytes.count >= prefixByteCount else {
			throw SEALError.truncatedEnvelope(
				byteCount: bytes.count, required: prefixByteCount)
		}
		let base = bytes.startIndex
		guard Array(bytes[base..<(base + magic.count)]) == magic else {
			throw SEALError.invalidEnvelopeMagic
		}
		let version = bytes[base + 4]
		guard version == currentVersion else {
			throw SEALError.unsupportedEnvelopeVersion(version)
		}
		let profile = bytes[base + 5]
		guard profile == profileReadOnly else {
			throw SEALError.unsupportedEnvelopeProfile(profile)
		}
		let segmentMax = uint32(bytes, at: base + 10)
		guard supportedSegmentMaxValues.contains(segmentMax) else {
			throw SEALError.unsupportedEnvelopeSegmentMax(segmentMax)
		}
		let configuration = try SEALConfiguration(
			profile: .readOnly,
			aeadID: uint16(bytes, at: base + 6),
			kdfID: uint16(bytes, at: base + 8),
			segmentMax: segmentMax,
			epochLength: bytes[base + 14])
		return SEALEnvelope(
			version: version, configuration: configuration,
			objectOffset: prefixByteCount)
	}

	/// The segmentation implied by an envelope's **total** size, prefix included — the
	/// number a `Content-Length` or file size gives directly.
	///
	/// The returned geometry's byte ranges address the envelope, not the object, so they
	/// can be issued as range requests against the stored blob unmodified. Its
	/// plaintext-space accessors are unaffected by the prefix.
	public func geometry(envelopeByteCount: Int) throws -> SEALLinearGeometry {
		guard envelopeByteCount >= objectOffset else {
			throw SEALError.truncatedEnvelope(
				byteCount: envelopeByteCount, required: objectOffset)
		}
		return try configuration.linearGeometry(
			objectByteCount: envelopeByteCount - objectOffset, baseOffset: objectOffset)
	}

	/// Parse however much of an envelope has arrived — the interrupted-download entry
	/// point, and the natural pairing for this format: the prefix lands in the first
	/// ``prefixByteCount`` octets, so the suite is known from the opening chunk without
	/// any out-of-band configuration.
	///
	/// ``SEALLinearPrefix/resumeOffset`` addresses the stored blob, so it can be issued
	/// as the next range request unmodified. The reading rules are unchanged — see
	/// ``SEALLinearPrefix``, in particular that the last whole block stays ambiguous
	/// until more bytes arrive or the transfer ends.
	public func parsePrefix(_ envelopeBytes: Data) throws -> SEALLinearPrefix {
		guard envelopeBytes.count >= objectOffset else {
			throw SEALError.truncatedEnvelope(
				byteCount: envelopeBytes.count, required: objectOffset)
		}
		let start = envelopeBytes.startIndex + objectOffset
		return try configuration.parsePrefix(
			envelopeBytes[start...], baseOffset: objectOffset)
	}

	/// Verify the commitment and return a reader, given the head of an envelope: the
	/// prefix and header block, or any longer run such as the whole thing.
	///
	/// A wrong CEK, a tampered prefix, a wrong `G`, or a corrupted header all fail here.
	public func startDecryption(
		cek: Data, envelopeBytes: Data, globalAssociatedData: Data = Data()
	) throws -> SEALReader {
		guard envelopeBytes.count >= objectOffset else {
			throw SEALError.truncatedEnvelope(
				byteCount: envelopeBytes.count, required: objectOffset)
		}
		let start = envelopeBytes.startIndex + objectOffset
		return try configuration.startDecryption(
			cek: cek, headerBlock: envelopeBytes[start...],
			globalAssociatedData: globalAssociatedData)
	}

	/// ``parse(_:)`` and ``startDecryption(cek:envelopeBytes:globalAssociatedData:)`` in
	/// one call — the entry point for reading a blob whose suite is not known in
	/// advance.
	public static func startDecryption(
		cek: Data, envelopeBytes: Data, globalAssociatedData: Data = Data()
	) throws -> (envelope: SEALEnvelope, reader: SEALReader) {
		let envelope = try parse(envelopeBytes)
		let reader = try envelope.startDecryption(
			cek: cek, envelopeBytes: envelopeBytes,
			globalAssociatedData: globalAssociatedData)
		return (envelope, reader)
	}

	/// Open a whole envelope, resolving its suite from the prefix: no
	/// ``SEALConfiguration`` needed in advance.
	///
	/// As with ``SEALConfiguration/open(_:cek:globalAssociatedData:)`` the final segment
	/// is opened with `is_final = 1`, so truncation and extension fail authentication.
	public static func open(
		_ envelope: Data, cek: Data, globalAssociatedData: Data = Data()
	) throws -> Data {
		let parsed = try parse(envelope)
		let start = envelope.startIndex + parsed.objectOffset
		return try parsed.configuration.open(
			envelope[start...], cek: cek, globalAssociatedData: globalAssociatedData)
	}
}

// MARK: - Fixed-width integers

private func bigEndian(_ value: UInt16) -> [UInt8] {
	[UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
}

private func bigEndian(_ value: UInt32) -> [UInt8] {
	(0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * (3 - $0))) }
}

private func uint16(_ bytes: Data, at index: Data.Index) -> UInt16 {
	UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
}

private func uint32(_ bytes: Data, at index: Data.Index) -> UInt32 {
	(0..<4).reduce(UInt32(0)) { $0 << 8 | UInt32(bytes[index + $1]) }
}
