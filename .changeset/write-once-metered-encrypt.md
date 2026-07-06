---
"@germ-network/swift-raae": patch
---

Close the unmetered encrypt path for the write-once non-MRAE pairing. §4.5.3.2
licenses derived nonce mode with a non-MRAE AEAD only under a one-encryption-per-
segment discipline, but `Segment.encryptDerived` — an unmetered static, and the API the
README example pattern reaches for — would happily encrypt the same position twice on a
`SEAL-RO-v1` AES-GCM/ChaCha20-Poly1305 schedule: fixed-nonce reuse, i.e. keystream
reuse and GHASH key recovery. Two changes:

- `Segment.encryptDerived` now refuses write-once non-MRAE schedules with the new
  `SegmentError.writeOnceRequiresMeteredEncryptor`, steering callers to
  `PayloadEncryptor.encryptDerived` (which delegates to an internal unmetered core
  after charging the budget). Decryption is unaffected — it carries no nonce-reuse
  hazard. MRAE (AES-256-GCM-SIV) and mutable-profile schedules are unchanged.
- In that configuration `PayloadEncryptor`'s per-segment cap (one encryption) now
  hard-stops under **both** policies: exceeding it is nonce reuse, not a statistical
  budget, so `.warn` no longer lets the rewrite through. `onBudgetEvent` still fires
  and counters do not advance past the refused encryption.

Cross-process/multi-writer discipline (seeding counters via `persistableState`)
remains the host's obligation.
