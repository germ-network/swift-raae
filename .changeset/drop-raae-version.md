---
"@germ-network/swift-raae": minor
---

Remove the stale `RAAE.version` constant.

It was documented as the package version but was frozen at `"0.0.1"` from the commit
that introduced it: changesets only edits `package.json`, and nothing in the package,
its tests, or its docs ever read it — so it drifted through the 0.1.0, 0.2.0 and 0.3.0
releases unnoticed. A runtime version accessor is not cheaply derivable in a SwiftPM
library (no bundle to read it from), so the honest options were to delete it or to
generate it at release time; this deletes it. `RAAE.targetedDraft` remains, and is
maintained.
