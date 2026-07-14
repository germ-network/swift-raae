---
"@germ-network/swift-raae": patch
---

Global associated data (G) and the SEAL-simple preset for MLS attachments
(draft-sullivan-mls-attachments). `PayloadSchedule.init` and `startDecrypt` gain a
`globalAAD` parameter (default empty) bound into the commitment derivation as an
extra framed element after `payload_info` (§4.5.1). Values are byte-exact against
the published draft: the empty default is framed as a zero-length element
(Appendix F.1) and non-empty values match Appendix F.2. The vendored
`commitment_hex` corpus carries the published always-framed-G values (convention
note in `Spec/NOTES.md`). New `SEALSimple` (named `SEAL-attachment` in raae-01,
renamed in -02) packages the §4.12 named instantiation the attachments draft
consumes: SEAL-RO-v1, derived nonces, 65536-octet segments, `epoch_length` 32,
`snap_id` 0x0000, `commitment_length` Nh, header `salt(32) || commitment(Nh)`,
linear segments at `offset(i) = (32+Nh) + i·(65536+16)`, `G = object_id`
(non-empty, ≤ 255 octets), an MLS cipher-suite → AEAD/KDF id mapping, a metered
write-once `Writer`, a commitment-verified random-access `Reader`, and one-shot
encrypt/decrypt.
