---
"@germ-network/swift-raae": patch
---

Fix a reachable panic (DoS) on the verify-before-decrypt path. `PayloadSchedule.init`
only lower-bounded the commitment length, so an over-long `publishedCommitment` — which
`startDecrypt(...)` derives `commitmentLength` from, and which is untrusted on the decrypt
path — would trap in `Bytes.uint16` (length > 0xFFFF) or HKDF `expand` (length > 255·Nh)
during commitment derivation, *before* the §4.6 verification ran. A single malformed
commitment field could abort any decryptor with no key knowledge.

`init` now upper-bounds the commitment length at `min(255·Nh, 0xFFFE)` (the most the KDF
can emit / the framing can encode; a commitment never needs to exceed `Nh`) and throws the
new `ScheduleError.commitmentTooLong(_:)` instead of aborting the process.
