---
"@germ-network/swift-raae": patch
---

Document the host contract the engine cannot enforce. New "Host obligations" section
on the DocC landing page, with matching notes on the relevant symbols:

- `PayloadInfo.salt`: must be unique per object under a CEK — shared `(CEK,
  payload_info)` means a shared key schedule, making segments (or whole objects)
  mutually substitutable with valid commitments and snapshots.
- `MaskedMultisetHash.verify`: SnapVerify proves set integrity, not recency — a
  complete old `(segments, snapshot)` pair replays; freshness/rollback binding is the
  host's job.
- `MaskedMultisetHash.accumulator`/`rewrittenAccumulator`: the raw accumulator is
  unmasked internal state kept for O(1) rewrites — publish only `snapshotValue`.

Also updates the README/DocC usage examples to the metered `PayloadEncryptor` path
(the sanctioned encrypt path since it owns nonce generation and budget tracking), and
fixes a stale `startDecrypt` DocC link that predated the `expectedCommitmentLength`
parameter.
