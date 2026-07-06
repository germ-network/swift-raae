---
"@germ-network/swift-raae": patch
---

Enforce `nonce_mode` consistency on every segment path. `nonce_mode` is committed into
the key schedule (§4.4), but `Segment.encryptRandom`/`decryptRandom` accepted a
derived-mode schedule (the reverse direction only failed incidentally, via the missing
`nonce_base`), letting a host emit or consume segments that contradict the object's
committed `payload_info`. All four `Segment` paths now check the schedule's mode first
and throw the new `SegmentError.nonceModeMismatch(scheduleMode:)`; the
`PayloadEncryptor` paths inherit the guard. `missingNonceBase` remains as a defensive
error but is no longer reachable through the public API.
