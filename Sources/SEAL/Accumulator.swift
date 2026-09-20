import Crypto
import RAAE
import SecretBytes

/// XOR a public `delta` into a held snapshot accumulator, returning fresh zeroizing
/// storage.
///
/// The accumulator is secret while it is unwrapped — the published mask is derived
/// from `snap_key`, so `acc` alone must never leave the writer/rewriter. The gated
/// path writes the result straight into its final zeroizing allocation; the fallback
/// XORs in a transient `[UInt8]` (what the pre-5.0 code did) but still hands the
/// long-lived copy to `SecretBytes`.
func xorIntoSecret(_ secret: SecretBytes, _ delta: [UInt8]) -> SecretBytes {
	precondition(delta.count == secret.byteCount, "accumulator XOR width mismatch")
	#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
		if #available(macOS 27, iOS 27, *), !forceArrayPath {
			return spanXorIntoSecret(secret, delta)
		}
		return heapXorIntoSecret(secret, delta)
	#elseif canImport(CryptoKit)
		return heapXorIntoSecret(secret, delta)
	#else
		return forceArrayPath
			? heapXorIntoSecret(secret, delta) : spanXorIntoSecret(secret, delta)
	#endif
}

/// Fallback: XOR through a transient `[UInt8]`.
private func heapXorIntoSecret(_ secret: SecretBytes, _ delta: [UInt8]) -> SecretBytes {
	var out = secret.withUnsafeBytes { Array($0) }
	for i in out.indices { out[i] ^= delta[i] }
	return try! SecretBytes(bytes: out)
}

// The zeroizing XOR — same three-branch availability shape as the KDF's framing tail
// and swift-secret-bytes' own span file.
#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	private func spanXorIntoSecret(_ secret: SecretBytes, _ delta: [UInt8]) -> SecretBytes {
		precondition(delta.count == secret.byteCount, "accumulator XOR width mismatch")
		return SecretBytes(byteCount: secret.byteCount) { span in
			secret.withUnsafeBytes { bytes in
				for i in 0..<delta.count { span.append(bytes[i] ^ delta[i]) }
			}
		}
	}
#elseif canImport(CryptoKit)
	// Darwin against an older SDK: CryptoKit lacks the span members, so the caller
	// takes the heap fallback.
#else
	private func spanXorIntoSecret(_ secret: SecretBytes, _ delta: [UInt8]) -> SecretBytes {
		precondition(delta.count == secret.byteCount, "accumulator XOR width mismatch")
		return SecretBytes(byteCount: secret.byteCount) { span in
			secret.withUnsafeBytes { bytes in
				for i in 0..<delta.count { span.append(bytes[i] ^ delta[i]) }
			}
		}
	}
#endif
