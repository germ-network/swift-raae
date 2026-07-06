# Appendix E test vectors

Conformance vectors extracted from the vendored draft snapshot (see
`Spec/SOURCE.md`). One JSON file per vector group (E.1, E.5, E.9, E.16.1, E.17.1);
`E16.json` also embeds the E.20.1 negative SnapVerify case, which tampers with
E.16.1's object. File names follow the draft's current appendix numbering.

Populated starting in Stage 1. This placeholder keeps the resource directory present
so `Package.swift`'s `.copy("Vectors")` resolves.
