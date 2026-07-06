/// RAAE — random-access authenticated encryption (raAE) and the SEAL construction,
/// per draft-sullivan-cfrg-raae.
///
/// This release exposes the verified low-level **engine**: ``PayloadInfo``,
/// ``PayloadSchedule`` (key schedule + commitment), ``Segment`` (per-segment
/// encrypt/decrypt in both nonce modes), and ``MaskedMultisetHash`` (the snapshot
/// authenticator), all selected through ``SuiteRegistry``. An ergonomic whole-message
/// facade is intentionally deferred to a later release.
///
/// > Warning: Pre-release, tracking an early individual Internet-Draft. The API is
/// > unstable and the implementation is unaudited — not for production use.
public enum RAAE {
	/// The draft revision this package targets. See `Spec/SOURCE.md`.
	public static let targetedDraft = "draft-sullivan-cfrg-raae (2026-07-06 snapshot)"

	/// Package version.
	public static let version = "0.0.1"
}
