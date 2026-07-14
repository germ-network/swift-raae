---
"@germ-network/swift-raae": minor
---

Resync the conformance target to the published draft-sullivan-cfrg-raae-02 (2026-07-13).

**Breaking:** `SEALScheme` follows draft-02's named-instantiation rename — `.attachment`
→ `.simple` (draft-02 `SEAL-simple`, the `SEAL-RO-v1` write-once preset) and `.simple`
→ `.editable` (draft-02 `SEAL-editable`, the `SEAL-RW-v1` 65536 random preset). draft-02
reassigns the name `SEAL-attachment` to a new epoch-digest-tree scheme this engine does
not implement.

Everything implemented is byte-identical between draft-01/-latest and -02, so the deltas
are: the rename above; the test vectors' move to Appendix F (E.1→F.1, E.5→F.5, E.9→F.9,
E.16.1→F.16.1, E.17.1→F.17.1, E.20.1→F.22.1); the newly-vendored **F.23** `SEAL-simple`
end-to-end KAT (schedule, derived nonce, segment, and stored object, cross-checked
against an independent from-scratch KDF); and documentation of draft-02's `snap_id`
0x0002 (digest transcript) / 0x0003 (epoch digest tree) and AEAD `AEGIS-256X2` (0x0024),
all unimplemented and rejected. `RAAE.targetedDraft` now reads
`draft-sullivan-cfrg-raae-02 (2026-07-13)`.
