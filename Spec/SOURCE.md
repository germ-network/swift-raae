# Spec source

This package implements **draft-sullivan-cfrg-raae** — "SEAL: Random-Access
Authenticated Encryption".

- **Conformance target:** the published
  [draft-sullivan-cfrg-raae-02](https://www.ietf.org/archive/id/draft-sullivan-cfrg-raae-02.html)
  (2026-07-13; individual draft, Informational, not yet CFRG-adopted)
- **Source repo (living `-latest`):** https://github.com/grittygrease/draft-sullivan-cfrg-raae
  (rendered at <https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html>)
- **Resynced to `-02` on:** 2026-07-13

> ⚠️ When re-capturing, diff against the **HTML** rendering: the IETF `.txt`
> renderings drop `f` characters from ligature sequences (`fi`/`ff`/`fl`) —
> *including inside hex values* — so they cannot be used to verify vectors.

## 2026-07-13 resync (`-01` → `-02`)

Everything this package implements is byte-identical between `-01` and `-02`
(verified section by section: §4.3 KDF/framing, §4.5 schedule/`G`/nonces, §4.6
commitment, §4.7.4 masked multiset hash, §5.9 budgets, and every vendored vector
value). The `-02` changes that touched this package:

- **Appendix renumbering E → F** (a new informative Appendix E holds a SEAL-simple
  implementation sketch). Vector files, test names, and docs use the F numbering:

  | -01 (E) | -02 (F) | vector |
  |---------|---------|--------|
  | E.1     | F.1     | single segment, AES-256-GCM, 16384 |
  | E.2     | F.2     | commitment with global associated data |
  | E.5     | F.5     | single segment, ChaCha20-Poly1305, 16384 |
  | E.9     | F.9     | two segment, AES-256-GCM, 16384 |
  | E.16.1  | F.16.1  | two segment, AES-256-GCM, 65536 (rewrite) |
  | E.17.1  | F.17.1  | two segment, AES-256-GCM-SIV, 65536 (derived, rewrite) |
  | E.20.1  | F.22.1  | negative SnapVerify (tampered accumulator) |
  | —       | F.23    | SEAL-simple(HKDF-SHA-256, AES-256-GCM) end-to-end (**newly vendored**) |

- **Named-instantiation rename (§4.12):** `-01`'s `SEAL-attachment` is now
  **`SEAL-simple`**, and the name `SEAL-attachment` was rebound to a *different* new
  write-once instantiation (epoch digest tree `snap_id` 0x0003, aligned layout,
  epoch_length 10 — **not implemented**; nor is `SEAL-attachment-small`,
  `snap_id` 0x0002). The Swift type was renamed `SEALAttachment` → `SEALSimple`
  accordingly (breaking). The MLS companion `draft-sullivan-mls-attachments-00`
  references the linear-layout scheme, i.e. `SEAL-simple`.
- **Profile-tuple enforcement (§4.10.2):** the MUST that a `(nonce_mode, snap_id)`
  tuple be valid for its named profile (present in `-01` too) is now enforced in
  `PayloadSchedule.init` — see the safety rail in `NOTES.md`.
- **New snap_ids** 0x0002 (digest transcript, §4.7.5) and 0x0003 (epoch digest tree,
  §4.7.6) are defined but **not implemented**: rejected as `unsupportedSnapID`, like
  any code point this build cannot honor.
- **New AEAD** AEGIS-256X2 (`aead_id` 0x0024) joins Table 10, and the AEAD table
  gains a per-AEAD `epoch_length` column (AEGIS suites pin a flat key, 63). AEGIS is
  Stage 4 (`STAGE4-FEASIBILITY.md`); no change for the implemented AEADs.

## History

- **2026-07-06 refresh:** the draft inserted vector groups (E.2 global-AAD, E.3
  KDF-combiner, per-suite 65536 variants, ...), renumbering the vendored ones
  (2026-06-26 → 2026-07-06: E.1→E.1, E.3→E.5, E.7→E.9, E.14.1→E.16.1, E.15.1→E.17.1,
  E.17.1→E.20.1); values unchanged.
- **Empty-G commitment resync:** the published `-01` (2026-07-06) frames an *empty*
  global associated data `G` as a zero-length element in **every** commitment
  derivation, regenerating the corpus's commitment values (F.1 is `47ea0ec7…`, was
  the pre-G `020e115b…`). The vendored `commitment_hex` values carry the published
  values; all other schedule values and ciphertexts were unaffected (`G` binds into
  the commitment only). The commitment is a stored, wire-visible value, so the
  `germ-network/mls-rs` companion must switch conventions in lockstep for empty-G
  objects (MLS attachment objects carry a non-empty `object_id` and interoperate
  across both conventions).

## Vectors

The Appendix F test vectors are the conformance oracle for every stage. They are
extracted into `Tests/RAAETests/Vectors/*.json`; every vendored commitment is also
pinned to its published literal in `GlobalAADTests`, and F.23 end-to-end in
`SEALSimpleTests`. On any spec refresh: diff the new revision against the target
above, re-extract changed vectors, bump the target here, and re-run the test suite.
