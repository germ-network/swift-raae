---
"@germ-network/swift-raae": minor
---

Ship the reduced immutable linear layout (§4.11.4) as the adopter API, so
`SEALScheme.simple` plus the container is now a complete `SEAL-simple(aead_id, kdf_id)`
named instantiation rather than a parameter preset.

```
object = salt(32) || commitment(Nh) || (ct_0||tag_0) || ... || (ct_{n-1}||tag_{n-1})
```

`SEALConfiguration.seal(_:cek:globalAssociatedData:)` / `open(_:cek:globalAssociatedData:)`
are one-call whole-payload operations over `Foundation.Data` (the engine and core stay
`[UInt8]`). Because large objects should not have to be held whole, the pieces beneath
them are public too: `SealedObjectHeader.encoded` and `parseHeader` for the stored
header block, `SEALLinearGeometry` (`linearGeometry(objectByteCount:)`) which maps
segments to byte ranges — and to raw plaintext offsets — from a byte count alone,
`SEALReader.decrypt(block:at:)` for random access, and `SEALLinearPrefix`/`parsePrefix`
for interrupted downloads, which reports how many blocks are provably interior and
where to resume.

Nothing but salt, commitment and segments is on the wire: no magic, version, segment
count, length prefixes, `is_final` octet, or `payload_info`. Boundaries are implicit
(non-final segments are full `segment_max`), and finality is bound in the derived
nonce, so completeness is proven by the last segment opening under `is_final = 1` —
the truncation defense under `SEAL-RO-v1`, where no snapshot runs. Pinned byte-exact
against the F.23 KAT in both directions.

Deliberate deviation: the spec permits `n_seg = 0`, but an empty object is
indistinguishable from one whose segments were all deleted, so `seal` always emits at
least one (possibly empty) final segment and `open` rejects zero-segment objects
(`SEALError.emptyImmutableObject`). Prefix parsing still accepts a header with no
segments — a partial download claims nothing about completeness.

New `SEALError` cases: `immutableLayoutRequiresReadOnlyProfile`, `truncatedHeaderBlock`,
`malformedSegmentation`, `emptyImmutableObject`. The layout was implemented against
draft-02 directly: §4.11 is the one section that drifted from the vendored 2026-07-06
snapshot (see `Spec/SOURCE.md`).
