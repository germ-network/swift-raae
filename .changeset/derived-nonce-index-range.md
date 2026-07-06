---
"@germ-network/swift-raae": patch
---

Reject derived-mode segment indices ≥ 2^63 instead of silently truncating. The derived
nonce is `nonce_base XOR ((i<<1)|is_final)` (§4.5.3), and Swift's `<<` discards the
shifted-out top bit, so an index ≥ 2^63 produced the same nonce as `index − 2^63`. Not
exploitable as shipped — indices 2^63 apart always fall in different epochs for
`epoch_length ≤ 63` and therefore use different segment keys — but the draft's
nonce-injectivity assumption should not rest on epoch geometry. `Segment.derivedNonce`
(and the derived encrypt/decrypt paths through it) now throw the new
`SegmentError.indexTooLargeForDerivedMode(_:)` for indices ≥ 2^63; the largest legal
index `2^63 − 1` still derives the exact spec value.
