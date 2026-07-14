---
"@germ-network/swift-raae": patch
---

Global associated data (G) and the SEAL-attachment preset for MLS attachments
(draft-sullivan-mls-attachments). `PayloadSchedule.init` and `startDecrypt` gain a
`globalAAD` parameter (default empty) bound into the commitment derivation as an
extra framed element after `payload_info` (§4.5.1). Values are byte-exact against
draft-sullivan-cfrg-raae-01: the empty default is framed as a zero-length element
(Appendix E.1) and non-empty values match Appendix E.2. The vendored Appendix E
`commitment_hex` corpus was resynced to the -01 values (convention note in
`Spec/NOTES.md`). New `SEALAttachment`
packages the §4.12 named instantiation the attachments draft consumes: SEAL-RO-v1,
derived nonces, 65536-octet segments, `epoch_length` 32, `snap_id` 0x0000,
`commitment_length` Nh, header `salt(32) || commitment(Nh)`, linear segments at
`offset(i) = (32+Nh) + i·(65536+16)`, `G = object_id` (non-empty, ≤ 255 octets),
an MLS cipher-suite → AEAD/KDF id mapping, a metered write-once `Writer`, a
commitment-verified random-access `Reader`, and one-shot encrypt/decrypt.
