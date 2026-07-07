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
/// A typical flow: build a ``SEALConfiguration``, author with
/// ``SEALConfiguration/startEncryption(cek:globalAssociatedData:)`` →
/// ``SEALWriter``, and read with
/// ``SEALConfiguration/startDecryption(cek:header:globalAssociatedData:)`` →
/// ``SEALReader``. In-place rewriting (`SEAL-RW-v1`) arrives with the Stage-C
/// rewriter (see `Spec/SEAL-ENGINE-PLAN.md`).
///
/// > Warning: Pre-release, tracking an early individual Internet-Draft. The API is
/// > unstable and the implementation is unaudited — not for production use.
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

// Index bounds: the engine enforces exactly the spec's — the §4.5.3.2 derived-mode
// bound (`index < 2^63`) lives in the core and propagates; random mode has no
// architectural index limit. Some other implementations additionally cap segment
// indices at 2^48 as a cross-implementation convention; this engine deliberately
// does not (spec-exact accept/reject set) — revisit only if ecosystem interop
// demands the shared cap. See Spec/SEAL-ENGINE-PLAN.md §2.4.
