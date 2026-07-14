import Crypto
import Foundation

/// A key derivation function as parameterized by the draft (Table 11), exposing the
/// single entry point `KDF(protocol_id, label, ikm, info, L)` from §4.3.
///
/// `ikm` and `info` are *lists* of byte strings; each element is framed individually
/// by `encode`. Implementations come in two styles — two-step (HKDF Extract→Expand)
/// and one-step (XOF). Stage 1 ships the HKDF style; TurboSHAKE lands in Stage 4.
public protocol KeyDerivation: Sendable {
	/// Output size of the native primitive, in octets (`Nh` in the draft).
	var outputSize: Int { get }

	/// `kdf_id` from Table 11.
	var id: UInt16 { get }

	/// `LH(x)` — the over-large-field digest used by framing (§4.3), label `"raAE-LP-v1"`.
	func longHash(_ field: [UInt8]) -> [UInt8]

	/// `KDF(protocol_id, label, ikm, info, L)` (§4.3), returning raw octets. Use this for
	/// **non-secret** outputs (commitment, snapshot contributions/tags/masks, `longHash`).
	func derive(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: [[UInt8]],
		info: [[UInt8]],
		outputLength: Int
	) -> [UInt8]

	/// Same derivation as ``derive(protocolID:label:ikm:info:outputLength:)`` but returns a
	/// zeroizing `SymmetricKey`. Use this for **secret** outputs (payload/epoch/snapshot
	/// keys, nonce base) so the long-lived copy is scrubbed on `deinit`.
	///
	/// - Note: the framing step still materializes the secret `ikm` in a transient
	///   `[UInt8]` buffer (`extract_input`), which Swift cannot scrub; this only bounds the
	///   *long-lived* secret to one zeroizing buffer.
	func deriveKey(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: [[UInt8]],
		info: [[UInt8]],
		outputLength: Int
	) -> SymmetricKey
}

extension KeyDerivation {
	/// Convenience: framing `encode` bound to this KDF's `longHash`.
	func encode(_ fields: [[UInt8]]) -> [UInt8] {
		Framing.encode(fields, longHash: longHash)
	}
}

/// Label for the over-large-field digest `LH` (draft §4.3).
private let longHashLabel = Bytes.ascii("raAE-LP-v1")

/// Two-step HKDF KDF (draft §4.3, Table 11). Generic over the swift-crypto hash.
struct HKDFKeyDerivation<H: HashFunction>: KeyDerivation {
	let id: UInt16

	var outputSize: Int { H.Digest.byteCount }

	/// `LH(x) = Extract(salt="raAE-LP-v1", ikm=x)`, sized to `Nh`.
	func longHash(_ field: [UInt8]) -> [UInt8] {
		let prk = HKDF<H>.extract(
			inputKeyMaterial: SymmetricKey(data: field),
			salt: longHashLabel
		)
		return prk.withUnsafeBytes { Array($0) }
	}

	func derive(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: [[UInt8]],
		info: [[UInt8]],
		outputLength: Int
	) -> [UInt8] {
		expandKey(
			protocolID: protocolID, label: label, ikm: ikm, info: info,
			outputLength: outputLength
		)
		.withUnsafeBytes { Array($0) }
	}

	func deriveKey(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: [[UInt8]],
		info: [[UInt8]],
		outputLength: Int
	) -> SymmetricKey {
		expandKey(
			protocolID: protocolID, label: label, ikm: ikm, info: info,
			outputLength: outputLength)
	}

	/// Shared HKDF Extract→Expand, returning the `SymmetricKey` directly (no `[UInt8]` copy).
	private func expandKey(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: [[UInt8]],
		info: [[UInt8]],
		outputLength: Int
	) -> SymmetricKey {
		// extract_input = encode(protocol_id, label, ...ikm)
		let extractInput = encode([protocolID, label] + ikm)
		// prk = Extract(salt=protocol_id, ikm=extract_input)
		let prk = HKDF<H>.extract(
			inputKeyMaterial: SymmetricKey(data: extractInput),
			salt: protocolID
		)
		// expand_info = encode(protocol_id, label, ...info, uint16(L))
		let expandInfo = encode([protocolID, label] + info + [Bytes.uint16(outputLength)])
		// return Expand(prk, expand_info, L)
		return HKDF<H>.expand(
			pseudoRandomKey: prk,
			info: expandInfo,
			outputByteCount: outputLength
		)
	}
}

/// HKDF-SHA-256, `kdf_id = 0x0001`, `Nh = 32` (Table 11).
func makeHKDFSHA256() -> HKDFKeyDerivation<SHA256> { .init(id: 0x0001) }

/// HKDF-SHA-384, `kdf_id = 0x0002`, `Nh = 48` (Table 11).
func makeHKDFSHA384() -> HKDFKeyDerivation<SHA384> { .init(id: 0x0002) }

/// HKDF-SHA-512, `kdf_id = 0x0003`, `Nh = 64` (Table 11).
func makeHKDFSHA512() -> HKDFKeyDerivation<SHA512> { .init(id: 0x0003) }
