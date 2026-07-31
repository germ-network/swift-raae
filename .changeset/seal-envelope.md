---
"@germ-network/swift-raae": minor
---

Add `SEALEnvelope`, a self-describing wrapper that carries the cipher suite alongside a
stored object, so a blob can be read without a `SEALConfiguration` supplied from
application context.

```
envelope = magic(4) || version(1) || profile(1) || aead_id(2) || kdf_id(2)
           || segment_max(4) || epoch_length(1) || object
```

A bare object carries no suite descriptor, and `kdf_id` fixes `Nh` and so the header
width — a reader must already know the suite to locate the first segment, and a
parameter mismatch reports only a commitment failure without naming the field (§6.3).
`SEALConfiguration.sealEnvelope(_:cek:globalAssociatedData:)` and the static
`SEALEnvelope.parse`/`open`/`startDecryption` close that gap; `SEALEnvelope.geometry(envelopeByteCount:)`
returns a `SEALLinearGeometry` whose byte ranges address the envelope, so range fetches
work unchanged.

This framing is ours, not the draft's — §4.11 delegates the layer to the consuming
protocol — and it is additive: dropping `objectOffset` octets leaves the §4.11.4 object
byte-identical to what `seal` produces, which is what other implementations read. The
prefix is unauthenticated but commitment-bound: every field it declares feeds key
derivation (the suite through `payload_info`, the profile through `protocol_id`), so
altering one fails the commitment before any AEAD operation rather than downgrading
anything. Parsing allowlists each field first and reports the offending one by name,
per §6.3. Read-only in v1; the profile octet is reserved for a future read-write layout.

`segment_max` is held to SEAL's §4.10 values (16384, 65536) on both encode and parse —
stricter than the core's power-of-two ≥ 4096 (§4.2.1), so no configuration can emit an
envelope its own parser would reject. Bare `seal`/`open` keep the looser rule.

New `SEALError` cases: `invalidEnvelopeMagic`, `truncatedEnvelope`,
`unsupportedEnvelopeVersion`, `unsupportedEnvelopeProfile`, `unsupportedEnvelopeSegmentMax`.
`SEALLinearGeometry` gains `baseOffset` (0 for a bare object), which
`byteRange(ofSegment:)` includes and the plaintext-space accessors do not.
