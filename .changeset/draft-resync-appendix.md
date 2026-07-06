---
"@germ-network/swift-raae": patch
---

Resync the pinned draft snapshot to 2026-07-06 and fix the vector appendix
numbering. The draft inserted new Appendix E vector groups, renumbering the
vendored ones (E.3→E.5, E.7→E.9, E.14.1→E.16.1, E.15.1→E.17.1, negative
E.17.1→E.20.1; E.1 unchanged). Every vendored byte value was re-verified against
the new snapshot — values are unchanged, so this is a numbering/documentation
sync only: vector files, test names, `RAAE.targetedDraft`, and docs now use the
2026-07-06 numbering (mapping table in `Spec/SOURCE.md`).
