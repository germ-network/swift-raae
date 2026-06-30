---
"@germ-network/swift-raae": patch
---

Security hardening from the self-review:
- H1: segment-AAD framing now uses the message KDF's real `LH`, so associated data
  larger than 65534 octets is bound distinctly (previously distinct large `A_i` collided).
- H2: `PayloadSchedule.init` rejects derived nonce mode with a non-MRAE AEAD
  (`AEAD.isMRAE`); a rewrite would otherwise reuse a segment's fixed nonce. Only
  AES-256-GCM-SIV is permitted for derived mode today.
- M1: the CEK is validated to be exactly 32 octets.
