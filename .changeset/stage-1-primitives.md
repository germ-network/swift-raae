---
"@germ-network/swift-raae": patch
---

Stage 1: primitive abstraction layer and KDF framing. Adds pluggable `AEAD` and
`KeyDerivation` protocols with swift-crypto backends (AES-256-GCM, ChaCha20-Poly1305,
HKDF-SHA-256/512), the length-prefixed `frame`/`encode` KDF framing (§4.3), the
`KDF(protocol_id, label, ikm, info, L)` two-step construction, and the suite registry
mapping the draft's `aead_id`/`kdf_id` (Tables 7–8). No public SEAL API yet.
