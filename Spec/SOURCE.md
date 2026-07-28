# Spec source

This package implements **draft-sullivan-cfrg-raae** — "SEAL: Random-Access
Authenticated Encryption".

- **Conformance target:** the published **draft-sullivan-cfrg-raae-02** (2026-07-13),
  <https://www.ietf.org/archive/id/draft-sullivan-cfrg-raae-02.html> (individual
  draft, Informational, not yet CFRG-adopted).
- **Transcription reference (vendored):** the `-latest` snapshot dated 2026-07-06,
  captured from <https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html>
  and stored at `Spec/draft-2026-07-06.html`. This snapshot is **byte-identical to
  -02 for every feature this package implements** (verified section-by-section: the
  KDF/framing §4.3, schedule/G §4.5, commitment §4.6, masked multiset hash §4.7.4,
  and all vendored vector values). -02's additions are documented under "draft-02
  resync" below; none is implemented here, so the vendored snapshot remains an
  accurate transcription source.
- **Source repo:** https://github.com/grittygrease/draft-sullivan-cfrg-raae

## draft-02 resync

-02 is the first *published, versioned* revision (the earlier `-01` and the vendored
`-latest` snapshot share -02's crypto for what we implement). This package's
conformance target moved to -02; the deltas that landed:

- **Appendix E → F.** -02 moved the test vectors to Appendix F. The vendored vectors
  are renumbered (values byte-identical): E.1→**F.1**, E.5→**F.5**, E.9→**F.9**,
  E.16.1→**F.16.1**, E.17.1→**F.17.1**, and the embedded negative case E.20.1→**F.22.1**.
  Files, `Vectors.load(...)` keys, test names, and docs now use F-numbering.
- **F.23 vendored.** -02 adds a full end-to-end KAT for the `SEAL-simple` named
  instantiation (`SEAL-RO-v1`, AES-256-GCM, HKDF-SHA-256, derived nonce, `snap_id`
  0x0000, epoch 32, 65536, empty `G`). Vendored as `F23.json` and pinned by
  `SEALSimpleVectorTests` (commitment `c081f669…`, cross-checked against an
  independent from-scratch KDF).
- **Named-instantiation rename.** -02 renamed `SEAL-attachment`→`SEAL-simple` (the
  RO-v1 write-once row) and `SEAL-simple`→`SEAL-editable` (the RW-v1 65536 random
  row); the engine's `SEALScheme` cases follow (`.simple`, `.editable`).
- **Not implemented (rejected/absent), newly defined by -02:** `snap_id` 0x0002
  (digest transcript) and 0x0003 (epoch digest tree) — rejected as unsupported; the
  new `SEAL-attachment` / `SEAL-attachment-small` instantiations (which need those
  authenticators); and AEAD `AEGIS-256X2` (0x0024).
- **Table renumbering.** -02 shifted the table numbers: AEAD 7→**10**, KDF 8→**11**,
  snapshot-authenticator (`snap_id`) 9→**12**, nonce-mode 10→**13**, profiles
  13→**14**, named instantiations 15→**16**. Source doc-comments below cite the
  vendored snapshot's numbering (matching the vendored HTML); `NOTES.md` and the
  engine cite -02 numbers where a -02-renamed entity is referenced.

## 2026-07-06 refresh

The vendored vector *values* are unchanged from the 2026-06-26 snapshot (every hex
value was re-verified against the new snapshot's Appendix E), but the draft inserted
new vector groups (E.2 global-AAD, E.3 KDF-combiner, per-suite 65536 variants, ...),
renumbering the ones we vendor:

| 2026-06-26 | 2026-07-06 | vector |
|------------|------------|--------|
| E.1        | E.1        | single segment, AES-256-GCM, 16384 |
| E.3        | E.5        | single segment, ChaCha20-Poly1305, 16384 |
| E.7        | E.9        | two segment, AES-256-GCM, 16384 |
| E.14.1     | E.16.1     | two segment, AES-256-GCM, 65536 (rewrite) |
| E.15.1     | E.17.1     | two segment, AES-256-GCM-SIV, 65536 (derived, rewrite) |
| E.17.1     | E.20.1     | negative SnapVerify (tampered accumulator) |

(That refresh used the then-current 2026-07-06 Appendix E numbering; the vectors
subsequently moved to draft-02's Appendix F — see "draft-02 resync" above.)

## Why a vendored snapshot?

The draft is served from a living `-latest` URL with no frozen revision, so it will
change. We pin conformance to the published, versioned **-02** and vendor the
byte-identical 2026-07-06 `-latest` snapshot as the frozen transcription reference.
On any spec refresh: re-capture the HTML, re-extract the Appendix F vectors into
`Tests/RAAETests/Vectors/`, bump the target/snapshot here, and re-run the test suite.

## Vectors

The Appendix F test vectors are the conformance oracle for every stage. They are
extracted (once, from the snapshot) into `Tests/RAAETests/Vectors/*.json`.

The HTML snapshot is vendored at `Spec/draft-2026-07-06.html` (captured 2026-07-06,
552 KB). Normative transcriptions in `NOTES.md` (KDF layer, profiles §4.10.2, named
instantiations §4.12) are made against this snapshot, never against the living
`-latest` URL.

### Intra-day drift: the §4.6 `G` element

The `-latest` draft changed *between* the PR #13 vector extraction and the snapshot
capture (same calendar date): §4.6 now binds the global associated data `G` as one
framed element appended after `payload_info` in the **commitment** derivation
(`[...payload_info, G]`, empty `G` still framed), and Appendix E gained the E.2
G-binding vector group. Consequences, verified value-by-value against the snapshot:

- Every vendored vector's `commitment_hex` changed and was re-pinned from the
  snapshot (E.1/E.9, E.5, E.16.1, E.17.1) — each also re-derived byte-exact with an
  independent from-scratch implementation of the labeled KDF.
- **Every other vendored value is unchanged** (all 89 non-commitment hex values were
  located verbatim in the snapshot): `payload_key`, `acc_key`, `nonce_base`, segment
  keys, nonces, ciphertexts, tags, and snapshots do not bind `G`.
- F.2 (`G` empty ⇒ the F.1 commitment; `G = "raae-demo-g"`) is pinned in
  `GlobalAADCommitmentTests`. (This vector group was E.2 in the vendored snapshot.)
