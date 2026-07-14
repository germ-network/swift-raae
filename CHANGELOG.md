# @germ-network/swift-raae

## 0.1.0

### Minor Changes

- [#11](https://github.com/germ-network/swift-raae/pull/11) [`660abb9`](https://github.com/germ-network/swift-raae/commit/660abb9885cf6e7da3fa4da0230f22d692da7486) Thanks [@germ-mark](https://github.com/germ-mark)! - Security review follow-ups M2–M4:

  - M2: `PayloadSchedule.startDecrypt(...)` re-derives and constant-time-verifies the
    published commitment before returning a schedule (the recommended safe path; enforced
    by convention, not the type system). `verifyCommitment(_:)` is the standalone §4.6 check.
  - M3: usage-limit support (§5.9). `PayloadSchedule.usageBudget(...)` returns the per-key
    log2 bounds; the opt-in `PayloadEncryptor` meters per-epoch-key (and, in derived mode,
    per-segment) encryptions with warn/enforce policies, delegating to the byte-exact
    segment statics. Counter state round-trips via `persistableState` / `seed(...)`.
  - M4: derived key material is no longer on the public API (§5.8) and is held as zeroizing
    `SymmetricKey`; `AEAD.seal/open` take `SymmetricKey`.

  BREAKING: PayloadSchedule no longer vends payloadKey/snapKey/nonceBase/segmentKey, and the
  AEAD protocol's key parameters are now SymmetricKey.

- [#15](https://github.com/germ-network/swift-raae/pull/15) [`ad7bea0`](https://github.com/germ-network/swift-raae/commit/ad7bea01d344574b06f5b49e5aaa034e6c703a72) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage B of the two-product construction: the SEAL engine's configuration and
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
  hard caps only (no warn mode) and no counter seeding. Counter persistence for
  _rewriting finalized objects_ ships with the Stage-C rewriter (`SEALUsageState`);
  there is deliberately **no mid-authoring resume** — the salt is writer-internal, so
  an interrupted authoring session restarts under a fresh salt and its partial output
  is unusable (crypto-safe, work lost). `UsageBudget`/`usageBudget()` remain as the
  informational §5.9 surface. README/DocC now lead with the SEAL product.

- [#15](https://github.com/germ-network/swift-raae/pull/15) [`ad7bea0`](https://github.com/germ-network/swift-raae/commit/ad7bea01d344574b06f5b49e5aaa034e6c703a72) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage C of the SEAL engine: the `SEAL-RW-v1` rewriter and the §4.12
  named-instantiation presets.

  - `SEALConfiguration.resumeWriting(cek:header:snapshot:segments:usageState:globalAssociatedData:)`
    → `SEALRewriter`: only constructible for the mutable profile ("an encryptor MUST
    NOT rewrite" under `SEAL-RO-v1`), and the constructor performs the full read-path
    verification — commitment, then SnapVerify + the finality rule over the presented
    set — before recovering the accumulator internally by unmasking the verified
    snapshot (`acc = wrapped_acc XOR mask(n_seg, snapshot_tag)`; the raw accumulator
    never crosses the API in either direction).
  - `rewrite(_:replacing:associatedData:)` is `RewriteSeg` (§4.9.2) as one operation:
    a fresh encryption at the preserved position (index and finality), the O(1)
    `remove/add` accumulator update, and the re-derived snapshot. Stale segment copies
    (a tag no longer in the verified set) are rejected; §5.9 budgets continue from the
    persisted `SEALUsageState` with hard caps, including the §5.9.7.4 per-segment
    hot-rewrite pool in derived mode. Pinned **byte-exact** against the Appendix
    E.17.1 deterministic rewrite (AES-256-GCM-SIV), including the
    same-plaintext-rewrite identity; the random-mode path is exercised over the
    E.16.1 vector state.
  - `SEALUsageState` (§5.9.5 freeze/resume): `SealedObject` and the rewriter both
    expose the counters; hand them back to the next `resumeWriting` so budgets survive
    a freeze. Losing them means the object stays frozen.
  - `SEALScheme` presets from Table 15 (attachment / simple / memory / disk /
    compact): each row fixes profile, `segment_max`, `nonce_mode` (overriding the
    per-AEAD default — `SEAL-simple` is random-nonce even for the MRAE suite), and
    epoch length; `SEAL-compact` requires an MRAE AEAD. The spec rows also bind a
    serialization layout the engine does not ship, so these are documented as
    parameter presets, not claimable named instantiations.

- [#15](https://github.com/germ-network/swift-raae/pull/15) [`ad7bea0`](https://github.com/germ-network/swift-raae/commit/ad7bea01d344574b06f5b49e5aaa034e6c703a72) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage A of the two-product construction (`Spec/SEAL-ENGINE-PLAN.md`): add the `SEAL`
  library product — the high-level engine that will expose the spec's lifecycle API
  (§3.2–3.3, §4.9) over the granular RAAE core. Stage A ships the profile type
  (`SEALProfile`, pinning the §4.10.2 wire protocol IDs) and the engine caps
  (`SEALLimits.maxSegments = 2^48`, deliberately stricter than the spec's derived-mode
  `2^63` bound for cross-implementation accept/reject symmetry). The configuration,
  writer, and reader land in Stage B.

  BREAKING (pre-release 0.0.x): the pinned-nonce seam
  `Segment.encryptRandom(schedule:position:associatedData:plaintext:nonce:)` and the
  unmetered derived-mode core are now `package`-scoped — reachable by the package's own
  byte-exact KATs and the SEAL engine target, never by consumers. Outside the package,
  random-mode encryption goes through the nonce-generating `PayloadEncryptor` (and the
  SEAL writer once Stage B lands), so a consumer can no longer supply — or reuse — a
  nonce. Decrypt statics and all other core APIs are unchanged.

- [#13](https://github.com/germ-network/swift-raae/pull/13) [`32ada02`](https://github.com/germ-network/swift-raae/commit/32ada02db659aa7e5393d5e251d25b6a36deb09b) Thanks [@germ-mark](https://github.com/germ-mark)! - Spec conformance: derived nonce mode with a non-MRAE AEAD is now permitted under the
  write-once `SEAL-RO-v1` profile, per the draft's §4.5.3.2 ("with a non-MRAE AEAD,
  derived nonce mode MUST be confined to a write-once profile"). The MRAE requirement
  still applies under `SEAL-RW-v1` and any unrecognized protocol ID (strict by default;
  the draft imposes no write-once obligations on custom profiles).

  - `PayloadSchedule.isWriteOnceProfile` reports whether the schedule's protocol ID
    selects the write-once profile.
  - `usageBudget()` gains a write-once branch for the newly legal configuration:
    `perSegmentLog2 = 0` (each segment encrypted exactly once — `PayloadEncryptor`
    now meters the write-once discipline for a single live writer) and
    `perEpochKeyLog2 = epoch_length` (the `2^r` segment indices an epoch key covers),
    replacing the MRAE synthetic-IV birthday math that does not apply to non-MRAE AEADs.
  - New `SEAL-RO-v1` KAT pinning the schedule derivations byte-exact (generated with an
    independent implementation of the draft's labeled-KDF construction, itself verified
    against the Appendix E.1 vector).

### Patch Changes

- [#15](https://github.com/germ-network/swift-raae/pull/15) [`ad7bea0`](https://github.com/germ-network/swift-raae/commit/ad7bea01d344574b06f5b49e5aaa034e6c703a72) Thanks [@germ-mark](https://github.com/germ-mark)! - Bind the §4.6 global associated data `G` into the commitment. The draft (vendored
  2026-07-06 snapshot) derives the commitment as
  `KDF(protocol_id, "commit", [CEK], [...payload_info, G], commitment_length)` — `G` is
  whole-message application context (a name, version, or policy), committed as one
  framed element after `payload_info`, never stored, supplied by the decryptor, with the
  empty default still committed as an empty final frame. Only the commitment binds `G`;
  all other schedule keys are unchanged.

  `PayloadSchedule.init` and `startDecrypt` gain `globalAssociatedData: [UInt8] = []`.
  A wrong (or omitted) `G` fails as `CommitmentError.commitmentMismatch`, exactly like a
  wrong CEK. New `GlobalAADCommitmentTests` pins Appendix E.2 (empty `G` ⇒ the E.1
  commitment; `G = "raae-demo-g"`), and every vendored vector's commitment was re-pinned
  from the snapshot and cross-checked against an independent from-scratch implementation
  of the labeled KDF.

  BREAKING (pre-release 0.0.x): commitments derived by earlier 0.0.x builds (which did
  not frame the `G` element) no longer verify — re-derive and re-store commitments for
  any existing objects. Segment ciphertexts, keys, and snapshots are unaffected.

- [#12](https://github.com/germ-network/swift-raae/pull/12) [`4098752`](https://github.com/germ-network/swift-raae/commit/4098752caec336a152f58fb9537698259ba10ff9) Thanks [@germ-mark](https://github.com/germ-mark)! - Fix a reachable panic (DoS) on the verify-before-decrypt path. `PayloadSchedule.init`
  only lower-bounded the commitment length, so an over-long `publishedCommitment` — which
  `startDecrypt(...)` derives `commitmentLength` from, and which is untrusted on the decrypt
  path — would trap in `Bytes.uint16` (length > 0xFFFF) or HKDF `expand` (length > 255·Nh)
  during commitment derivation, _before_ the §4.6 verification ran. A single malformed
  commitment field could abort any decryptor with no key knowledge.

  `init` now upper-bounds the commitment length at `min(255·Nh, 0xFFFE)` (the most the KDF
  can emit / the framing can encode; a commitment never needs to exceed `Nh`) and throws the
  new `ScheduleError.commitmentTooLong(_:)` instead of aborting the process.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Document the security meaning of the commitment-length floor. The §4.6 minimum of 16
  octets bounds the key-committing property at ~2^64 collision resistance (birthday on
  the truncated output) against multi-key / invisible-salamander-style adversaries.
  `minCommitmentLength` and the `PayloadSchedule.init` `commitmentLength` parameter now
  say so explicitly and recommend keeping the default full-`Nh` commitment; the floor
  exists for interop, not as a target. Documentation only — no behavior change.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Reject derived-mode segment indices ≥ 2^63 instead of silently truncating. The derived
  nonce is `nonce_base XOR ((i<<1)|is_final)` (§4.5.3), and Swift's `<<` discards the
  shifted-out top bit, so an index ≥ 2^63 produced the same nonce as `index − 2^63`. Not
  exploitable as shipped — indices 2^63 apart always fall in different epochs for
  `epoch_length ≤ 63` and therefore use different segment keys — but the draft's
  nonce-injectivity assumption should not rest on epoch geometry. `Segment.derivedNonce`
  (and the derived encrypt/decrypt paths through it) now throw the new
  `SegmentError.indexTooLargeForDerivedMode(_:)` for indices ≥ 2^63; the largest legal
  index `2^63 − 1` still derives the exact spec value.

- [#13](https://github.com/germ-network/swift-raae/pull/13) [`32ada02`](https://github.com/germ-network/swift-raae/commit/32ada02db659aa7e5393d5e251d25b6a36deb09b) Thanks [@germ-mark](https://github.com/germ-mark)! - Resync the pinned draft snapshot to 2026-07-06 and fix the vector appendix
  numbering. The draft inserted new Appendix E vector groups, renumbering the
  vendored ones (E.3→E.5, E.7→E.9, E.14.1→E.16.1, E.15.1→E.17.1, negative
  E.17.1→E.20.1; E.1 unchanged). Every vendored byte value was re-verified against
  the new snapshot — values are unchanged, so this is a numbering/documentation
  sync only: vector files, test names, `RAAE.targetedDraft`, and docs now use the
  2026-07-06 numbering (mapping table in `Spec/SOURCE.md`).

- [#15](https://github.com/germ-network/swift-raae/pull/15) [`ad7bea0`](https://github.com/germ-network/swift-raae/commit/ad7bea01d344574b06f5b49e5aaa034e6c703a72) Thanks [@germ-mark](https://github.com/germ-mark)! - Drop the engine's `2^48` segment-index cap; enforce exactly the spec's bounds. The
  cap was an ecosystem convention borrowed from other implementations, not a spec
  requirement — and it was applied unevenly (writer/reader checked it; the
  snapshot-verify and rewrite paths did not), recreating the very accept/reject
  asymmetry it exists to prevent. The engine now enforces only the spec: the §4.5.3.2
  derived-mode MUST (`index < 2^63`) propagates from the core through every engine
  path, and random mode is architecturally unbounded. `SEALLimits` and
  `SEALError.segmentIndexExceedsCap` are removed; the `2^48` convention is recorded in
  `Spec/SEAL-ENGINE-PLAN.md` §2.4 for reconsideration only if cross-implementation
  interop demands it (and then on every index-accepting path at once).

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Document the host contract the engine cannot enforce. New "Host obligations" section
  on the DocC landing page, with matching notes on the relevant symbols:

  - `PayloadInfo.salt`: must be unique per object under a CEK — shared `(CEK,
payload_info)` means a shared key schedule, making segments (or whole objects)
    mutually substitutable with valid commitments and snapshots.
  - `MaskedMultisetHash.verify`: SnapVerify proves set integrity, not recency — a
    complete old `(segments, snapshot)` pair replays; freshness/rollback binding is the
    host's job.
  - `MaskedMultisetHash.accumulator`/`rewrittenAccumulator`: the raw accumulator is
    unmasked internal state kept for O(1) rewrites — publish only `snapshotValue`.

  Also updates the README/DocC usage examples to the metered `PayloadEncryptor` path
  (the sanctioned encrypt path since it owns nonce generation and budget tracking), and
  fixes a stale `startDecrypt` DocC link that predated the `expectedCommitmentLength`
  parameter.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - `PayloadEncryptor.encryptRandom` now generates its nonce internally and returns it,
  instead of accepting a caller-supplied one. The §5.9.7.1 budget the encryptor meters
  assumes every encryption uses a fresh uniformly random nonce — a caller reusing a nonce
  silently voided the metered collision bound without the meter noticing. Callers that
  must pin a nonce (test vectors, interop reproduction) use the unmetered
  `Segment.encryptRandom`, which keeps its nonce parameter.

  BREAKING (pre-release 0.0.x): the `nonce:` parameter is removed from
  `PayloadEncryptor.encryptRandom`; the returned tuple still carries the nonce to store
  alongside the segment.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Enforce `nonce_mode` consistency on every segment path. `nonce_mode` is committed into
  the key schedule (§4.4), but `Segment.encryptRandom`/`decryptRandom` accepted a
  derived-mode schedule (the reverse direction only failed incidentally, via the missing
  `nonce_base`), letting a host emit or consume segments that contradict the object's
  committed `payload_info`. All four `Segment` paths now check the schedule's mode first
  and throw the new `SegmentError.nonceModeMismatch(scheduleMode:)`; the
  `PayloadEncryptor` paths inherit the guard. `missingNonceBase` remains as a defensive
  error but is no longer reachable through the public API.

- [#15](https://github.com/germ-network/swift-raae/pull/15) [`ad7bea0`](https://github.com/germ-network/swift-raae/commit/ad7bea01d344574b06f5b49e5aaa034e6c703a72) Thanks [@germ-mark](https://github.com/germ-mark)! - Enforce the §4.10.2 Table-13 profile tuples in `PayloadSchedule.init`. The vendored
  spec snapshot pins each named profile to specific `(nonce_mode, snap_id)` tuples —
  SEAL-RW-v1 requires `snap_id 0x0001` (the masked multiset hash, so every rewritable
  object carries whole-object integrity) with a random nonce or an MRAE derived nonce;
  SEAL-RO-v1 requires derived nonce + `snap_id 0x0000` (no snapshot authenticator runs;
  the finality bit is the truncation signal) — and "a decryptor MUST reject any object
  whose tuple is not" valid. The core accepted invalid pairings (RO + 0x0001,
  RW + 0x0000); it now throws the new
  `ScheduleError.invalidProfileTuple(nonceMode:snapID:)`. Unknown protocol IDs remain
  tuple-unconstrained (custom profiles carry their own rules) but keep the strict MRAE
  gate for derived mode.

  BREAKING (pre-release 0.0.x): schedules with Table-13-invalid tuples no longer
  construct. The SEAL-RO-v1 KAT was regenerated for the pinned tuple (snap_id 0x0000);
  it is now a self-generated regression pin — the KDF construction itself remains
  independently verified via the Appendix E vectors.

- [#9](https://github.com/germ-network/swift-raae/pull/9) [`fa4e858`](https://github.com/germ-network/swift-raae/commit/fa4e858337ebb6e80eb723d9cf916af4b16760a3) Thanks [@germ-mark](https://github.com/germ-mark)! - Security hardening from the self-review:

  - H1: segment-AAD framing now uses the message KDF's real `LH`, so associated data
    larger than 65534 octets is bound distinctly (previously distinct large `A_i` collided).
  - H2: `PayloadSchedule.init` rejects derived nonce mode with a non-MRAE AEAD
    (`AEAD.isMRAE`); a rewrite would otherwise reuse a segment's fixed nonce. Only
    AES-256-GCM-SIV is permitted for derived mode today.
  - M1: the CEK is validated to be exactly 32 octets.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Enforce `segment_max` (§4.4) on every segment path. `segment_max` was committed into
  the key schedule and used to compute the §5.9.7.4 per-segment usage budget
  (`perSegmentLog2 = birthday − log2 L`, with `L` the blocks per `segment_max`-sized
  segment), but no encrypt or decrypt path actually checked segment length — a host
  encrypting oversized segments got a data-volume bound that was quietly too generous
  while appearing metered.

  `Segment.encryptRandom`/`encryptDerived` now reject plaintexts longer than
  `segment_max`, and `decryptRandom`/`decryptDerived` reject a `ct||tag` whose implied
  plaintext length (`len − Nt`) exceeds it — before any AEAD work — with the new
  `Segment.SegmentError.exceedsSegmentMax(length:segmentMax:)`. `PayloadEncryptor`
  inherits the checks by delegation. Segments up to and including `segment_max` octets
  are unaffected.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Reject unknown `snap_id` values in `PayloadSchedule.init`. Unknown `aead_id`/`kdf_id`
  were already rejected via the suite registry, but any `snap_id` passed validation and
  was committed into the key schedule — binding a parameter this build cannot honor.
  `init` now throws the new `ScheduleError.unsupportedSnapID(_:)` for anything other than
  the Table-9 code points, exposed as the new `SnapID` constants (`SnapID.none = 0x0000`,
  `SnapID.maskedMultisetHash = 0x0001`) with the registry predicate
  `SuiteRegistry.isKnownSnapID(_:)`.

- [#14](https://github.com/germ-network/swift-raae/pull/14) [`1503bcb`](https://github.com/germ-network/swift-raae/commit/1503bcb48c5c3eb8023d37d3f9f5f4e978e1e1c2) Thanks [@germ-mark](https://github.com/germ-mark)! - Close the unmetered encrypt path for the write-once non-MRAE pairing. §4.5.3.2
  licenses derived nonce mode with a non-MRAE AEAD only under a one-encryption-per-
  segment discipline, but `Segment.encryptDerived` — an unmetered static, and the API the
  README example pattern reaches for — would happily encrypt the same position twice on a
  `SEAL-RO-v1` AES-GCM/ChaCha20-Poly1305 schedule: fixed-nonce reuse, i.e. keystream
  reuse and GHASH key recovery. Two changes:

  - `Segment.encryptDerived` now refuses write-once non-MRAE schedules with the new
    `SegmentError.writeOnceRequiresMeteredEncryptor`, steering callers to
    `PayloadEncryptor.encryptDerived` (which delegates to an internal unmetered core
    after charging the budget). Decryption is unaffected — it carries no nonce-reuse
    hazard. MRAE (AES-256-GCM-SIV) and mutable-profile schedules are unchanged.
  - In that configuration `PayloadEncryptor`'s per-segment cap (one encryption) now
    hard-stops under **both** policies: exceeding it is nonce reuse, not a statistical
    budget, so `.warn` no longer lets the rewrite through. `onBudgetEvent` still fires
    and counters do not advance past the refused encryption.

  Cross-process/multi-writer discipline (seeding counters via `persistableState`)
  remains the host's obligation.

## 0.0.1

### Patch Changes

- [#2](https://github.com/germ-network/swift-raae/pull/2) [`141fb99`](https://github.com/germ-network/swift-raae/commit/141fb99f1f1ef9627e0a9b4d3457395a9e8645dd) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 1: primitive abstraction layer and KDF framing. Adds pluggable `AEAD` and
  `KeyDerivation` protocols with swift-crypto backends (AES-256-GCM, ChaCha20-Poly1305,
  HKDF-SHA-256/512), the length-prefixed `frame`/`encode` KDF framing (§4.3), the
  `KDF(protocol_id, label, ikm, info, L)` two-step construction, and the suite registry
  mapping the draft's `aead_id`/`kdf_id` (Tables 7–8). No public SEAL API yet.

- [#4](https://github.com/germ-network/swift-raae/pull/4) [`4dfb8ee`](https://github.com/germ-network/swift-raae/commit/4dfb8ee1824deaea64603e0bb17b4ed7b557e795) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 2a: payload schedule, commitment, and single-segment (random nonce). Adds
  `PayloadInfo` (wire format + validation), `PayloadSchedule` (commitment, payload_key,
  acc_key, nonce_base, and epoch-based `segment_key`), and the random-mode segment AAD +
  encrypt/decrypt path. Verified byte-exact against the draft's Appendix E.1 vector
  (commitment, payload_key, acc_key, segment_aad, and ciphertext).

- [#5](https://github.com/germ-network/swift-raae/pull/5) [`e6c030b`](https://github.com/germ-network/swift-raae/commit/e6c030b667fe1b4ad4f3d947fe34df8d1ff68869) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 2b: derived nonce mode and multi-segment. Adds the derived-nonce construction
  (`nonce_base XOR ((i<<1)|is_final)`) with its empty-AAD rule, multi-segment
  encrypt/decrypt verified in arbitrary order, and the AES-128-GCM / HKDF-SHA-384 suite
  entries. Corrects two AEAD/KDF code points to their IANA values (ChaCha20-Poly1305 =
  0x001D, HKDF-SHA-512 = 0x0003) — caught by the E.3 vector. New byte-exact vectors: E.3
  (ChaCha20) and E.7 (two-segment).

- [#6](https://github.com/germ-network/swift-raae/pull/6) [`ad786be`](https://github.com/germ-network/swift-raae/commit/ad786bef294b962ce974599b676dc78ce4c04cfc) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 3: masked multiset hash snapshot authenticator and mutable interface. Adds
  contribution/accumulator/snapshot-tag/mask derivation, the published snapshot value,
  O(1) rewrite accumulator updates, and constant-time SnapVerify. Verified byte-exact
  against Appendix E.1 (n=1), E.7 (n=2), the E.14.1 rewrite, and the E.17.1 negative
  SnapVerify vector.

- [#7](https://github.com/germ-network/swift-raae/pull/7) [`9062ea9`](https://github.com/germ-network/swift-raae/commit/9062ea96fb6b36884636fdaafda0541297dea040) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 4: AES-256-GCM-SIV (the MRAE suite for derived-nonce rewrites) via swift-crypto's
  \_CryptoExtras, verified byte-exact against Appendix E.15.1 (derived nonces, deterministic
  re-encryption, same-nonce rewrite). Feasibility spike (Spec/STAGE4-FEASIBILITY.md)
  documents cutting AEGIS (needs libsodium/AES-NI) and deferring TurboSHAKE (hand-rolled
  Keccak) from v1.

- [#8](https://github.com/germ-network/swift-raae/pull/8) [`d480f05`](https://github.com/germ-network/swift-raae/commit/d480f05e71e338e567de7443e59cd85bb5418a0b) Thanks [@germ-mark](https://github.com/germ-mark)! - Stage 5: expose the verified SEAL engine as public API (PayloadInfo, PayloadSchedule,
  Segment, MaskedMultisetHash, ConstantTime, SuiteRegistry, AEAD/KeyDerivation protocols,
  ProtocolID) with DocC and an end-to-end public-surface test. The ergonomic whole-message
  facade is deferred. First pre-release: 0.0.1.
