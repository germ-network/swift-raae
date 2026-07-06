---
"@germ-network/swift-raae": patch
---

`PayloadEncryptor.encryptRandom` now generates its nonce internally and returns it,
instead of accepting a caller-supplied one. The §5.9.7.1 budget the encryptor meters
assumes every encryption uses a fresh uniformly random nonce — a caller reusing a nonce
silently voided the metered collision bound without the meter noticing. Callers that
must pin a nonce (test vectors, interop reproduction) use the unmetered
`Segment.encryptRandom`, which keeps its nonce parameter.

BREAKING (pre-release 0.0.x): the `nonce:` parameter is removed from
`PayloadEncryptor.encryptRandom`; the returned tuple still carries the nonce to store
alongside the segment.
