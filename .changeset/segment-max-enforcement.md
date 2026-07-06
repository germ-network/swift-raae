---
"@germ-network/swift-raae": patch
---

Enforce `segment_max` (§4.4) on every segment path. `segment_max` was committed into
the key schedule and used to compute the §5.9.7.4 per-segment usage budget
(`perSegmentLog2 = birthday − log2 L`, with `L` the blocks per `segment_max`-sized
segment), but no encrypt or decrypt path actually checked segment length — a host
encrypting oversized segments got a data-volume bound that was quietly too generous
while appearing metered.

`Segment.encryptRandom`/`encryptDerived` now reject plaintexts longer than
`segment_max`, and `decryptRandom`/`decryptDerived` reject a `ct||tag` whose implied
plaintext length (`len − Nt`) exceeds it — before any AEAD work — with the new
`Segment.SegmentError.exceedsSegmentMax(length:segmentMax:)`. `PayloadEncryptor`
inherits the checks by delegation. Segments up to and including `segment_max` octets
are unaffected.
