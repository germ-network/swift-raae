---
"@germ-network/swift-raae": minor
---

Security review follow-ups M2–M4:
- M2: `PayloadSchedule.startDecrypt(...)` re-derives and constant-time-verifies the
  published commitment before returning a schedule (the recommended safe path; enforced
  by convention, not the type system). `verifyCommitment(_:)` is the standalone §4.6 check.
- M3: usage-limit support (§5.9). `PayloadSchedule.usageBudget(...)` returns the per-key
  log2 bounds; the opt-in `PayloadEncryptor` meters per-epoch-key (and, in derived mode,
  per-segment) encryptions with warn/enforce policies, delegating to the byte-exact
  segment statics. Counter state round-trips via `persistableState` / `seed(...)`.
- M4: derived key material is no longer on the public API (§5.8) and is held as zeroizing
  `SymmetricKey`; `AEAD.seal/open` take `SymmetricKey`.

BREAKING: PayloadSchedule no longer vends payloadKey/snapKey/nonceBase/segmentKey, and the
AEAD protocol's key parameters are now SymmetricKey.
