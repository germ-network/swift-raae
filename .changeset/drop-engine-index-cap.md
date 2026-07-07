---
"@germ-network/swift-raae": patch
---

Drop the engine's `2^48` segment-index cap; enforce exactly the spec's bounds. The
cap was an ecosystem convention borrowed from other implementations, not a spec
requirement — and it was applied unevenly (writer/reader checked it; the
snapshot-verify and rewrite paths did not), recreating the very accept/reject
asymmetry it exists to prevent. The engine now enforces only the spec: the §4.5.3.2
derived-mode MUST (`index < 2^63`) propagates from the core through every engine
path, and random mode is architecturally unbounded. `SEALLimits` and
`SEALError.segmentIndexExceedsCap` are removed; the `2^48` convention is recorded in
`Spec/SEAL-ENGINE-PLAN.md` §2.4 for reconsideration only if cross-implementation
interop demands it (and then on every index-accepting path at once).
