---
"@germ-network/swift-raae": minor
---

Stage A of the two-product construction (`Spec/SEAL-ENGINE-PLAN.md`): add the `SEAL`
library product — the high-level engine that will expose the spec's lifecycle API
(§3.2–3.3, §4.9) over the granular RAAE core. Stage A ships the profile type
(`SEALProfile`, pinning the §4.10.2 wire protocol IDs) and the engine caps
(`SEALLimits.maxSegments = 2^48`, deliberately stricter than the spec's derived-mode
`2^63` bound for cross-implementation accept/reject symmetry). The configuration,
writer, and reader land in Stage B.

BREAKING (pre-release 0.0.x): the pinned-nonce seam
`Segment.encryptRandom(schedule:position:associatedData:plaintext:nonce:)` and the
unmetered derived-mode core are now `package`-scoped — reachable by the package's own
byte-exact KATs and the SEAL engine target, never by consumers. Outside the package,
random-mode encryption goes through the nonce-generating `PayloadEncryptor` (and the
SEAL writer once Stage B lands), so a consumer can no longer supply — or reuse — a
nonce. Decrypt statics and all other core APIs are unchanged.
