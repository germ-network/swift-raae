---
"@germ-network/swift-raae": minor
---

Stage 2a: payload schedule, commitment, and single-segment (random nonce). Adds
`PayloadInfo` (wire format + validation), `PayloadSchedule` (commitment, payload_key,
acc_key, nonce_base, and epoch-based `segment_key`), and the random-mode segment AAD +
encrypt/decrypt path. Verified byte-exact against the draft's Appendix E.1 vector
(commitment, payload_key, acc_key, segment_aad, and ciphertext).
