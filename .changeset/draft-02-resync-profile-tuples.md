---
"@germ-network/swift-raae": minor
---

Resync to the published draft-sullivan-cfrg-raae-02 (2026-07-13) and enforce the
§4.10.2 profile-tuple MUST. Everything implemented is byte-identical between -01
and -02; the -02 changes that land here:

- `PayloadSchedule.init` (and thus `startDecrypt`) now rejects `(nonce_mode,
  snap_id)` tuples that are invalid for the named profile with the new
  `ScheduleError.invalidProfileTuple`: `SEAL-RW-v1` requires the masked multiset
  hash, and `SEAL-RO-v1` requires a derived nonce with `snap_id` 0x0000. Unknown
  protocol IDs are unconstrained (custom profiles define their own tuples).
- Vendored vectors renumbered to -02's Appendix F (E.1→F.1, …, E.20.1→F.22.1) and
  the new F.23 `SEAL-simple(HKDF-SHA-256, AES-256-GCM)` end-to-end vector is
  vendored and pinned — schedule, derived nonce, segment, and stored object bytes.
- The -02-defined `snap_id` 0x0002 (digest transcript) and 0x0003 (epoch digest
  tree) remain rejected as unsupported; -02's new SEAL-attachment /
  SEAL-attachment-small instantiations (built on them) are not implemented.
