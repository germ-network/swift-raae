---
"@germ-network/swift-raae": minor
---

Spec conformance: derived nonce mode with a non-MRAE AEAD is now permitted under the
write-once `SEAL-RO-v1` profile, per the draft's §4.5.3.2 ("with a non-MRAE AEAD,
derived nonce mode MUST be confined to a write-once profile"). The MRAE requirement
still applies under `SEAL-RW-v1` and any unrecognized protocol ID (strict by default;
the draft imposes no write-once obligations on custom profiles).

- `PayloadSchedule.isWriteOnceProfile` reports whether the schedule's protocol ID
  selects the write-once profile.
- `usageBudget()` gains a write-once branch for the newly legal configuration:
  `perSegmentLog2 = 0` (each segment encrypted exactly once — `PayloadEncryptor`
  now meters the write-once discipline for a single live writer) and
  `perEpochKeyLog2 = epoch_length` (the `2^r` segment indices an epoch key covers),
  replacing the MRAE synthetic-IV birthday math that does not apply to non-MRAE AEADs.
- New `SEAL-RO-v1` KAT pinning the schedule derivations byte-exact (generated with an
  independent implementation of the draft's labeled-KDF construction, itself verified
  against the Appendix E.1 vector).
