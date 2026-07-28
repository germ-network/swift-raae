# Appendix F test vectors

Conformance vectors extracted from the vendored draft snapshot (see
`Spec/SOURCE.md`), renumbered to draft-02's Appendix F. One JSON file per vector group
(F.1, F.5, F.9, F.16.1, F.17.1, and F.23 — the `SEAL-simple` end-to-end KAT);
`F16.json` also embeds the F.22.1 negative SnapVerify case, which tampers with
F.16.1's object. File names follow the draft's current appendix numbering.

Populated starting in Stage 1. This placeholder keeps the resource directory present
so `Package.swift`'s `.copy("Vectors")` resolves.
