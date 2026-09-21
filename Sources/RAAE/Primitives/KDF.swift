import Crypto
import Foundation
import SecretBytes

/// A key derivation function as parameterized by the draft (Table 8), exposing the
/// single entry point `KDF(protocol_id, label, ikm, info, L)` from §4.3.
///
/// `ikm` is the derivation's secret input keying material — a single `SymmetricKey`,
/// since every derivation in the draft mixes exactly one secret — held in zeroizing
/// storage by the caller. `info` is a *list* of public byte strings; each element is
/// framed individually by `encode`. Implementations come in two styles — two-step
/// (HKDF Extract→Expand) and one-step (XOF). Stage 1 ships the HKDF style; TurboSHAKE
/// lands in Stage 4.
public protocol KeyDerivation: Sendable {
	/// Output size of the native primitive, in octets (`Nh` in the draft).
	var outputSize: Int { get }

	/// `kdf_id` from Table 8.
	var id: UInt16 { get }

	/// `LH(x)` — the over-large-field digest used by framing (§4.3), label `"raAE-LP-v1"`.
	func longHash(_ field: [UInt8]) -> [UInt8]

	/// `KDF(protocol_id, label, ikm, info, L)` (§4.3), returning raw octets. Use this for
	/// **non-secret** outputs (commitment, snapshot contributions/tags/masks, `longHash`).
	func derive(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: SymmetricKey,
		info: [[UInt8]],
		outputLength: Int
	) -> [UInt8]

	/// Same derivation as ``derive(protocolID:label:ikm:info:outputLength:)`` but returns a
	/// zeroizing `SymmetricKey`. Use this for **secret** outputs (payload/epoch/snapshot
	/// keys, nonce base) so the long-lived copy is scrubbed on `deinit`.
	///
	/// - Note: `ikm` arrives as a `SymmetricKey`, and the framing tail
	///   (`uint16(len) || ikm`) is written straight into zeroizing storage on platforms
	///   with the span surface; below that it is built in a transient `[UInt8]` buffer,
	///   which Swift cannot scrub — the pre-5.0 behaviour. Either way the *long-lived*
	///   secret stays in zeroizing storage.
	func deriveKey(
		protocolID: [UInt8],
		label: [UInt8],
		ikm: SymmetricKey,
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

/// Two-step HKDF KDF (draft §4.3, Table 8). Generic over the swift-crypto hash.
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
		ikm: SymmetricKey,
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
		ikm: SymmetricKey,
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
		ikm: SymmetricKey,
		info: [[UInt8]],
		outputLength: Int
	) -> SymmetricKey {
		// extract_input = frame(protocol_id) || frame(label) || frame(ikm), which for
		// every ikm this package derives (32–64 octets) is the literal framing
		// `uint16(len) || ikm` — byte-identical to encoding `[protocol_id, label, ikm]`.
		let prk = HKDF<H>.extract(
			inputKeyMaterial: extractInput(
				protocolID: protocolID, label: label, ikm: ikm),
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

	/// `frame(protocol_id) || frame(label) || frame(ikm)` as an `SymmetricKey`, so
	/// `Extract` never sees the secret on the heap where the platform allows it.
	private func extractInput(
		protocolID: [UInt8], label: [UInt8], ikm: SymmetricKey
	) -> SymmetricKey {
		let prefix = encode([protocolID, label])
		let ikmByteCount = ikm.withUnsafeBytes { $0.count }
		// An over-large ikm would take framing's `LH` escape, which needs the bytes
		// on the heap to digest them; no derivation here can reach that size.
		guard ikmByteCount <= Framing.maxLiteralLength else {
			return heapExtractInput(prefix: prefix, ikm: ikm)
		}
		#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
			if #available(macOS 27, iOS 27, *), !forceArrayPath {
				return Self.zeroizingExtractInput(
					prefix: prefix, ikmByteCount: ikmByteCount, ikm: ikm)
			}
			return heapExtractInput(prefix: prefix, ikm: ikm)
		#elseif canImport(CryptoKit)
			return heapExtractInput(prefix: prefix, ikm: ikm)
		#else
			if !forceArrayPath {
				return Self.zeroizingExtractInput(
					prefix: prefix, ikmByteCount: ikmByteCount, ikm: ikm)
			}
			return heapExtractInput(prefix: prefix, ikm: ikm)
		#endif
	}

	/// Fallback: the pre-5.0 framing, materializing `frame(ikm)` in a transient
	/// `[UInt8]` that Swift cannot scrub. `Framing.frame` (not a bare `uint16` prefix)
	/// so an over-large ikm still takes the `LH` escape the spec prescribes rather
	/// than trapping in `Bytes.uint16`.
	private func heapExtractInput(prefix: [UInt8], ikm: SymmetricKey) -> SymmetricKey {
		let ikmBytes = ikm.withUnsafeBytes { Array($0) }
		return SymmetricKey(data: prefix + Framing.frame(ikmBytes, longHash: longHash))
	}
}

// The zeroizing framing tail — the span surface is available on Darwin against an
// SDK that has it (OS-27-gated) and unconditionally on non-CryptoKit platforms.
// Mirrors the three-branch shape of swift-secret-bytes' `SecretBytesSpan.swift`.
#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	extension HKDFKeyDerivation {
		/// Writes `prefix || uint16(ikmByteCount) || ikm` directly into fresh zeroizing
		/// storage — no staging buffer holds the secret.
		static func zeroizingExtractInput(
			prefix: [UInt8], ikmByteCount: Int, ikm: SymmetricKey
		) -> SymmetricKey {
			let total = prefix.count + 2 + ikmByteCount
			let stored = SecretBytes(byteCount: total) { span in
				for byte in prefix { span.append(byte) }
				span.append(UInt8(truncatingIfNeeded: ikmByteCount >> 8))
				span.append(UInt8(truncatingIfNeeded: ikmByteCount))
				ikm.withUnsafeBytes { bytes in
					for byte in bytes { span.append(byte) }
				}
			}
			// A zeroizing→zeroizing copy: `Extract` takes a concrete `SymmetricKey`.
			return SymmetricKey(data: stored)
		}
	}
#elseif canImport(CryptoKit)
	// Darwin against an older SDK: CryptoKit lacks the span surface, so
	// `zeroizingExtractInput` is never declared and the caller takes the heap path.
#else
	extension HKDFKeyDerivation {
		/// Writes `prefix || uint16(ikmByteCount) || ikm` directly into fresh zeroizing
		/// storage — no staging buffer holds the secret.
		static func zeroizingExtractInput(
			prefix: [UInt8], ikmByteCount: Int, ikm: SymmetricKey
		) -> SymmetricKey {
			let total = prefix.count + 2 + ikmByteCount
			let stored = SecretBytes(byteCount: total) { span in
				for byte in prefix { span.append(byte) }
				span.append(UInt8(truncatingIfNeeded: ikmByteCount >> 8))
				span.append(UInt8(truncatingIfNeeded: ikmByteCount))
				ikm.withUnsafeBytes { bytes in
					for byte in bytes { span.append(byte) }
				}
			}
			// A zeroizing→zeroizing copy: `Extract` takes a concrete `SymmetricKey`.
			return SymmetricKey(data: stored)
		}
	}
#endif

/// HKDF-SHA-256, `kdf_id = 0x0001`, `Nh = 32` (Table 8).
func makeHKDFSHA256() -> HKDFKeyDerivation<SHA256> { .init(id: 0x0001) }

/// HKDF-SHA-384, `kdf_id = 0x0002`, `Nh = 48` (Table 8).
func makeHKDFSHA384() -> HKDFKeyDerivation<SHA384> { .init(id: 0x0002) }

/// HKDF-SHA-512, `kdf_id = 0x0003`, `Nh = 64` (Table 8).
func makeHKDFSHA512() -> HKDFKeyDerivation<SHA512> { .init(id: 0x0003) }
