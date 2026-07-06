import RAAE

/// SEAL — the high-level engine for random-access authenticated encryption, built on
/// the ``RAAE`` core per `draft-sullivan-cfrg-raae`.
///
/// The engine exposes the spec's lifecycle API (§3.2–3.3: `StartEnc` / `EncSeg` /
/// `StartDec` / `DecSeg` / `RewriteSeg` / `SnapVerify`) behind profile-pinned
/// configurations: nonce mode and snapshot choice are derived from the profile and
/// AEAD rather than caller-supplied, nonces and salts are generated internally, and
/// the raw accumulator never crosses the API boundary. The granular `RAAE` product
/// remains available for implementers and vector tooling.
///
/// > Warning: Stage-A scaffold (see `Spec/SEAL-ENGINE-PLAN.md`): this module currently
/// > ships the profile type and engine caps. The configuration, writer, and reader
/// > land in Stage B; until then, encryption goes through `RAAE.PayloadEncryptor`.
public enum SEALProfile: Equatable, Sendable {
	/// `SEAL-RO-v1` — the immutable write-once profile (§4.10.2): derived nonce mode,
	/// every segment encrypted exactly once.
	case readOnly
	/// `SEAL-RW-v1` — the mutable profile (§4.10.2): segments may be rewritten in
	/// place under the snapshot authenticator.
	case readWrite

	/// The profile's wire protocol identifier (§4.10.2).
	public var protocolID: [UInt8] {
		switch self {
		case .readOnly: ProtocolID.immutable
		case .readWrite: ProtocolID.mutable
		}
	}
}

/// Engine-level operational caps. These are deliberately stricter than the spec's own
/// bounds: the core stays spec-exact standalone, while the engine narrows the accept/
/// reject set for cross-implementation symmetry and platform safety.
public enum SEALLimits {
	/// Maximum segment count / exclusive segment-index bound, applied in both nonce
	/// modes. Stricter than the spec's derived-mode `index < 2^63` (§4.5.3.2): a
	/// fixed 2^48 cap keeps the engine's accept/reject set identical across
	/// implementations that adopt the same cap, leaves 15 bits of headroom below
	/// the nonce encoding's own ceiling against future wire changes, and is
	/// unreachable by any real object (2^48 segments of the minimum 4096-octet
	/// `segment_max` is a septillion-octet object).
	public static let maxSegments: UInt64 = 1 << 48
}
