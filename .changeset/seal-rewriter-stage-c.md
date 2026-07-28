---
"@germ-network/swift-raae": minor
---

Stage C of the SEAL engine: the `SEAL-RW-v1` rewriter and the §4.12
named-instantiation presets.

- `SEALConfiguration.resumeWriting(cek:header:snapshot:segments:usageState:globalAssociatedData:)`
  → `SEALRewriter`: only constructible for the mutable profile ("an encryptor MUST
  NOT rewrite" under `SEAL-RO-v1`), and the constructor performs the full read-path
  verification — commitment, then SnapVerify + the finality rule over the presented
  set — before recovering the accumulator internally by unmasking the verified
  snapshot (`acc = wrapped_acc XOR mask(n_seg, snapshot_tag)`; the raw accumulator
  never crosses the API in either direction).
- `rewrite(_:replacing:associatedData:)` is `RewriteSeg` (§4.9.2) as one operation:
  a fresh encryption at the preserved position (index and finality), the O(1)
  `remove/add` accumulator update, and the re-derived snapshot. Stale segment copies
  (a tag no longer in the verified set) are rejected; §5.9 budgets continue from the
  persisted `SEALUsageState` with hard caps, including the §5.9.7.4 per-segment
  hot-rewrite pool in derived mode. Pinned **byte-exact** against the Appendix
  E.17.1 deterministic rewrite (AES-256-GCM-SIV), including the
  same-plaintext-rewrite identity; the random-mode path is exercised over the
  E.16.1 vector state.
- `SEALUsageState` (§5.9.5 freeze/resume): `SealedObject` and the rewriter both
  expose the counters; hand them back to the next `resumeWriting` so budgets survive
  a freeze. Losing them means the object stays frozen.
- `SEALScheme` presets from the named-instantiation table (simple / editable /
  memory / disk / compact): each row fixes profile, `segment_max`, `nonce_mode`
  (overriding the per-AEAD default — `SEAL-editable` is random-nonce even for the
  MRAE suite), and epoch length; `SEAL-compact` requires an MRAE AEAD. The spec rows
  also bind a
  serialization layout the engine does not ship, so these are documented as
  parameter presets, not claimable named instantiations.
