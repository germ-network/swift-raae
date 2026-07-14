# Spec source

This package implements **draft-sullivan-cfrg-raae** — "SEAL: Random-Access
Authenticated Encryption".

- **Source (rendered):** https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html
- **Source repo:** https://github.com/grittygrease/draft-sullivan-cfrg-raae
- **Snapshot date:** 2026-07-06 (draft `-latest`; individual draft, Informational,
  not yet CFRG-adopted)
- **Captured for this repo on:** 2026-07-06

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

Vector files, test names, and docs now use the 2026-07-06 numbering.

## Why a vendored snapshot?

The draft is served from a living `-latest` URL with no frozen revision and is only
days old, so it will change. We pin to this dated snapshot as the conformance target.
On any spec refresh: re-capture the HTML, re-extract Appendix E vectors into
`Tests/RAAETests/Vectors/`, bump the snapshot date here, and re-run the test suite.

## Vectors

The Appendix E test vectors are the conformance oracle for every stage. They are
extracted (once, from this snapshot) into `Tests/RAAETests/Vectors/*.json`.

The HTML snapshot is vendored at `Spec/draft-2026-07-06.html` (captured 2026-07-06,
552 KB). Normative transcriptions in `NOTES.md` (KDF layer, profiles Table 13, named
instantiations Table 15) are made against this snapshot, never against the living
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
- E.2 (`G` empty ⇒ the E.1 commitment; `G = "raae-demo-g"`) is pinned in
  `GlobalAADCommitmentTests`.
