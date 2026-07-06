---
"@germ-network/swift-raae": patch
---

Enforce the §4.10.2 Table-13 profile tuples in `PayloadSchedule.init`. The vendored
spec snapshot pins each named profile to specific `(nonce_mode, snap_id)` tuples —
SEAL-RW-v1 requires `snap_id 0x0001` (the masked multiset hash, so every rewritable
object carries whole-object integrity) with a random nonce or an MRAE derived nonce;
SEAL-RO-v1 requires derived nonce + `snap_id 0x0000` (no snapshot authenticator runs;
the finality bit is the truncation signal) — and "a decryptor MUST reject any object
whose tuple is not" valid. The core accepted invalid pairings (RO + 0x0001,
RW + 0x0000); it now throws the new
`ScheduleError.invalidProfileTuple(nonceMode:snapID:)`. Unknown protocol IDs remain
tuple-unconstrained (custom profiles carry their own rules) but keep the strict MRAE
gate for derived mode.

BREAKING (pre-release 0.0.x): schedules with Table-13-invalid tuples no longer
construct. The SEAL-RO-v1 KAT was regenerated for the pinned tuple (snap_id 0x0000);
it is now a self-generated regression pin — the KDF construction itself remains
independently verified via the Appendix E vectors.
