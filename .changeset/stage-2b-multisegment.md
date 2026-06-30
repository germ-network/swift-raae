---
"@germ-network/swift-raae": patch
---

Stage 2b: derived nonce mode and multi-segment. Adds the derived-nonce construction
(`nonce_base XOR ((i<<1)|is_final)`) with its empty-AAD rule, multi-segment
encrypt/decrypt verified in arbitrary order, and the AES-128-GCM / HKDF-SHA-384 suite
entries. Corrects two AEAD/KDF code points to their IANA values (ChaCha20-Poly1305 =
0x001D, HKDF-SHA-512 = 0x0003) — caught by the E.3 vector. New byte-exact vectors: E.3
(ChaCha20) and E.7 (two-segment).
