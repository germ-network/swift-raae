# @germ-network/swift-raae

## 0.0.1

### Patch Changes

- [#2](https://github.com/germ-network/swift-raae/pull/2) [`141fb99`](https://github.com/germ-network/swift-raae/commit/141fb99f1f1ef9627e0a9b4d3457395a9e8645dd) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 1: primitive abstraction layer and KDF framing. Adds pluggable `AEAD` and
  `KeyDerivation` protocols with swift-crypto backends (AES-256-GCM, ChaCha20-Poly1305,
  HKDF-SHA-256/512), the length-prefixed `frame`/`encode` KDF framing (§4.3), the
  `KDF(protocol_id, label, ikm, info, L)` two-step construction, and the suite registry
  mapping the draft's `aead_id`/`kdf_id` (Tables 7–8). No public SEAL API yet.

- [#4](https://github.com/germ-network/swift-raae/pull/4) [`4dfb8ee`](https://github.com/germ-network/swift-raae/commit/4dfb8ee1824deaea64603e0bb17b4ed7b557e795) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 2a: payload schedule, commitment, and single-segment (random nonce). Adds
  `PayloadInfo` (wire format + validation), `PayloadSchedule` (commitment, payload_key,
  acc_key, nonce_base, and epoch-based `segment_key`), and the random-mode segment AAD +
  encrypt/decrypt path. Verified byte-exact against the draft's Appendix E.1 vector
  (commitment, payload_key, acc_key, segment_aad, and ciphertext).

- [#5](https://github.com/germ-network/swift-raae/pull/5) [`e6c030b`](https://github.com/germ-network/swift-raae/commit/e6c030b667fe1b4ad4f3d947fe34df8d1ff68869) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 2b: derived nonce mode and multi-segment. Adds the derived-nonce construction
  (`nonce_base XOR ((i<<1)|is_final)`) with its empty-AAD rule, multi-segment
  encrypt/decrypt verified in arbitrary order, and the AES-128-GCM / HKDF-SHA-384 suite
  entries. Corrects two AEAD/KDF code points to their IANA values (ChaCha20-Poly1305 =
  0x001D, HKDF-SHA-512 = 0x0003) — caught by the E.3 vector. New byte-exact vectors: E.3
  (ChaCha20) and E.7 (two-segment).

- [#6](https://github.com/germ-network/swift-raae/pull/6) [`ad786be`](https://github.com/germ-network/swift-raae/commit/ad786bef294b962ce974599b676dc78ce4c04cfc) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 3: masked multiset hash snapshot authenticator and mutable interface. Adds
  contribution/accumulator/snapshot-tag/mask derivation, the published snapshot value,
  O(1) rewrite accumulator updates, and constant-time SnapVerify. Verified byte-exact
  against Appendix E.1 (n=1), E.7 (n=2), the E.14.1 rewrite, and the E.17.1 negative
  SnapVerify vector.

- [#7](https://github.com/germ-network/swift-raae/pull/7) [`9062ea9`](https://github.com/germ-network/swift-raae/commit/9062ea96fb6b36884636fdaafda0541297dea040) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 4: AES-256-GCM-SIV (the MRAE suite for derived-nonce rewrites) via swift-crypto's
  \_CryptoExtras, verified byte-exact against Appendix E.15.1 (derived nonces, deterministic
  re-encryption, same-nonce rewrite). Feasibility spike (Spec/STAGE4-FEASIBILITY.md)
  documents cutting AEGIS (needs libsodium/AES-NI) and deferring TurboSHAKE (hand-rolled
  Keccak) from v1.

- [#8](https://github.com/germ-network/swift-raae/pull/8) [`d480f05`](https://github.com/germ-network/swift-raae/commit/d480f05e71e338e567de7443e59cd85bb5418a0b) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 5: expose the verified SEAL engine as public API (PayloadInfo, PayloadSchedule,
  Segment, MaskedMultisetHash, ConstantTime, SuiteRegistry, AEAD/KeyDerivation protocols,
  ProtocolID) with DocC and an end-to-end public-surface test. The ergonomic whole-message
  facade is deferred. First pre-release: 0.0.1.
