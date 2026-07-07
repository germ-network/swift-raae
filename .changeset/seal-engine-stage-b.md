---
"@germ-network/swift-raae": minor
---

Stage B of the two-product construction: the SEAL engine's configuration and
writer/reader lifecycle, shaped by the spec's abstract API (§3.2–3.3) and procedures
(§4.9). Every misuse edge the 0.0.1 review closed with runtime guards is
unrepresentable at this layer:

- `SEALConfiguration(profile:aeadID:kdfID:segmentMax:epochLength:)` — `nonce_mode`
  and `snap_id` are derived from the profile and AEAD (§4.10.2 Table 13, Table 9
  defaults), never caller-supplied; `commitment_length` is pinned to `Nh`;
  `generateCEK()` vends fresh CEKs.
- `startEncryption(cek:globalAssociatedData:)` → `SEALWriter`: generates the
  per-object salt and all nonces internally, meters the §5.9 budgets with hard caps,
  maintains the snapshot accumulator internally (it never crosses the API), writes
  each index exactly once (the RO write-once rule; RW in-place rewrite arrives with
  the Stage-C rewriter), and enforces the §4.11.1 finality shape at `finalize()`.
- `startDecryption(cek:header:globalAssociatedData:)` → `SEALReader`: the only
  reader constructor, and it verifies the commitment (wrong CEK/parameters/`G` fail
  before any decryption); the header must match the configuration in all but the
  salt. `verifySnapshot` implements SnapVerify plus the finality rule;
  `verifyFinality` is the §4.9.1.2 truncation check (the sole whole-object signal
  under `SEAL-RO-v1`); `decrypt` opens segments in any order.

BREAKING (pre-release 0.0.x): `PayloadEncryptor`, `BudgetPolicy`, `BudgetEvent`, and
`BudgetError` are removed from the RAAE core — the writer absorbed the metering, with
hard caps only (no warn mode) and no counter seeding (authoring freeze/resume returns
with the Stage-C rewriter). `UsageBudget`/`usageBudget()` remain as the informational
§5.9 surface. README/DocC now lead with the SEAL product.
