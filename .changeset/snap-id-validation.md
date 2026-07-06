---
"@germ-network/swift-raae": patch
---

Reject unknown `snap_id` values in `PayloadSchedule.init`. Unknown `aead_id`/`kdf_id`
were already rejected via the suite registry, but any `snap_id` passed validation and
was committed into the key schedule — binding a parameter this build cannot honor.
`init` now throws the new `ScheduleError.unsupportedSnapID(_:)` for anything other than
the Table-9 code points, exposed as the new `SnapID` constants (`SnapID.none = 0x0000`,
`SnapID.maskedMultisetHash = 0x0001`) with the registry predicate
`SuiteRegistry.isKnownSnapID(_:)`.
