---
"@germ-network/swift-raae": patch
---

Stage 3: masked multiset hash snapshot authenticator and mutable interface. Adds
contribution/accumulator/snapshot-tag/mask derivation, the published snapshot value,
O(1) rewrite accumulator updates, and constant-time SnapVerify. Verified byte-exact
against Appendix E.1 (n=1), E.7 (n=2), the E.14.1 rewrite, and the E.17.1 negative
SnapVerify vector.
