# Appendix E test vectors

Conformance vectors extracted from the vendored draft snapshot (see
`Spec/SOURCE.md`). One JSON file per vector group (E.1, E.5, E.9, E.16.1, E.17.1);
`E16.json` also embeds the E.20.1 negative SnapVerify case, which tampers with
E.16.1's object. File names follow the draft's current appendix numbering.

Each `commitment_hex` is the `draft-sullivan-cfrg-raae-01` value: `G` is always
framed as the last commitment element, so an empty `G` contributes a zero-length
element. All other fields are byte-identical to the vendored snapshot (`G` binds the
commitment only). See the resync note in `Spec/SOURCE.md`. All five resynced
commitments are pinned to their literals in `GlobalAADTests` (E.1 in
`emptyGMatchesVendoredE1Commitment`, the rest in
`resyncedEmptyGCommitmentsPinnedToDraft01`) and were cross-verified against an
independent from-scratch implementation of the §4.3 labeled KDF.

Populated starting in Stage 1. This placeholder keeps the resource directory present
so `Package.swift`'s `.copy("Vectors")` resolves.
