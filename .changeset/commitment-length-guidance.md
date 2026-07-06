---
"@germ-network/swift-raae": patch
---

Document the security meaning of the commitment-length floor. The §4.6 minimum of 16
octets bounds the key-committing property at ~2^64 collision resistance (birthday on
the truncated output) against multi-key / invisible-salamander-style adversaries.
`minCommitmentLength` and the `PayloadSchedule.init` `commitmentLength` parameter now
say so explicitly and recommend keeping the default full-`Nh` commitment; the floor
exists for interop, not as a target. Documentation only — no behavior change.
