---
"@germ-network/swift-raae": patch
---

Bind the §4.6 global associated data `G` into the commitment. The draft (vendored
2026-07-06 snapshot) derives the commitment as
`KDF(protocol_id, "commit", [CEK], [...payload_info, G], commitment_length)` — `G` is
whole-message application context (a name, version, or policy), committed as one
framed element after `payload_info`, never stored, supplied by the decryptor, with the
empty default still committed as an empty final frame. Only the commitment binds `G`;
all other schedule keys are unchanged.

`PayloadSchedule.init` and `startDecrypt` gain `globalAssociatedData: [UInt8] = []`.
A wrong (or omitted) `G` fails as `CommitmentError.commitmentMismatch`, exactly like a
wrong CEK. New `GlobalAADCommitmentTests` pins Appendix E.2 (empty `G` ⇒ the E.1
commitment; `G = "raae-demo-g"`), and every vendored vector's commitment was re-pinned
from the snapshot and cross-checked against an independent from-scratch implementation
of the labeled KDF.

BREAKING (pre-release 0.0.x): commitments derived by earlier 0.0.x builds (which did
not frame the `G` element) no longer verify — re-derive and re-store commitments for
any existing objects. Segment ciphertexts, keys, and snapshots are unaffected.
