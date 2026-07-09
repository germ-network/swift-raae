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

> ⚠️ **Known drift vs the published `-01`** (also dated 2026-07-06, at
> <https://www.ietf.org/archive/id/draft-sullivan-cfrg-raae-01.html>): `-01` frames
> an *empty* global associated data `G` as a zero-length element in **every**
> commitment derivation and regenerated the corpus's commitment values (its E.1
> commitment is `47ea0ec7…`; ours is the pre-G `020e115b…`). All other schedule
> values and ciphertexts are unaffected (`G` binds into the commitment only), and
> every **non-empty** `G` derives byte-identically under both conventions — pinned
> against `-01` Appendix E.2 in `GlobalAADTests`. See the convention note in
> `NOTES.md`; a full resync should adopt the always-include convention and update
> the vendored `commitment_hex` values.

## Why a vendored snapshot?

The draft is served from a living `-latest` URL with no frozen revision and is only
days old, so it will change. We pin to this dated snapshot as the conformance target.
On any spec refresh: re-capture the HTML, re-extract Appendix E vectors into
`Tests/RAAETests/Vectors/`, bump the snapshot date here, and re-run the test suite.

## Vectors

The Appendix E test vectors are the conformance oracle for every stage. They are
extracted (once, from this snapshot) into `Tests/RAAETests/Vectors/*.json`.

> TODO (Stage 1): download the HTML snapshot into `Spec/draft-2026-07-06.html` and
> extract Appendix E vectors to JSON. Left out of the initial commit to avoid
> vendoring a large HTML blob before the extraction tooling exists.
