---
"@germ-network/swift-raae": patch
---

Stage 4: AES-256-GCM-SIV (the MRAE suite for derived-nonce rewrites) via swift-crypto's
_CryptoExtras, verified byte-exact against Appendix E.15.1 (derived nonces, deterministic
re-encryption, same-nonce rewrite). Feasibility spike (Spec/STAGE4-FEASIBILITY.md)
documents cutting AEGIS (needs libsodium/AES-NI) and deferring TurboSHAKE (hand-rolled
Keccak) from v1.
