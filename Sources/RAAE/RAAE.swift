/// RAAE — random-access authenticated encryption (raAE) and the SEAL construction,
/// per draft-sullivan-cfrg-raae.
///
/// This is the granular **core**: ``PayloadInfo``, ``PayloadSchedule`` (key schedule +
/// commitment), ``Segment`` (per-segment encrypt/decrypt in both nonce modes), and
/// ``MaskedMultisetHash`` (the snapshot authenticator), all selected through
/// ``SuiteRegistry`` — the byte-exact conformance layer, for implementers and vector
/// tooling. Most consumers want the **SEAL** product instead: the engine that owns
/// salt/nonce generation, budgets, snapshot accounting, and verify-before-decrypt.
///
/// > Warning: Pre-release, tracking an early individual Internet-Draft. The API is
/// > unstable and the implementation is unaudited — not for production use.
public enum RAAE {
	/// The draft revision this package targets. See `Spec/SOURCE.md`.
	public static let targetedDraft = "draft-sullivan-cfrg-raae (2026-07-06 snapshot)"

	/// Package version.
	public static let version = "0.0.1"
}
