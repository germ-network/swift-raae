# Appendix F test vectors

Conformance vectors extracted from the published `draft-sullivan-cfrg-raae-02` (see
`Spec/SOURCE.md`). One JSON file per vector group (F.1, F.5, F.9, F.16.1, F.17.1,
F.23); `F16.json` also embeds the F.22.1 negative SnapVerify case, which tampers
with F.16.1's object. File names follow the draft's current appendix numbering
(Appendix E before `-02`).

`G` is always framed as the last commitment element, so an empty `G` contributes a
zero-length element (the published convention since `-01`). Every vendored
`commitment_hex` is pinned to its published literal in `GlobalAADTests` (F.1 in
`emptyGMatchesVendoredF1Commitment`, the rest in
`emptyGCommitmentsPinnedToPublishedDraft`) and was cross-verified against an
independent from-scratch implementation of the §4.3 labeled KDF. `F23.json` is the
SEAL-simple end-to-end vector, pinned in
`SEALSimpleTests.f23PublishedVectorRoundTrips`.

Populated starting in Stage 1. This placeholder keeps the resource directory present
so `Package.swift`'s `.copy("Vectors")` resolves.
