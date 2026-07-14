# SEAL engine plan — two-product construction (RAAE core + SEAL engine)

Splits the package into two layers: a granular, deterministic **RAAE core** (the
existing byte-exact primitives) and a high-level **SEAL engine** designed against the
draft spec (§3.2–3.3 abstract API, §4.9 procedures, §4.10.2 profiles). The goal:
every misuse edge the 0.0.1 security review closed with runtime guards (F1–F6)
becomes *unrepresentable* in the high-level API, while the granular core stays
available — mostly out of sight — for vectors, interop tooling, and advanced hosts.

## 1. Product structure

One SwiftPM package, two library products:

```
swift-raae/
  Sources/RAAE/    — core: granular, deterministic, byte-exact primitives (existing code)
  Sources/SEAL/    — engine: spec-shaped lifecycle API; depends on RAAE
```

- `RAAE` (core) keeps the granular API: `PayloadInfo`, `PayloadSchedule`, `Segment`,
  `MaskedMultisetHash`, `SuiteRegistry`, `ConstantTime`, the `AEAD`/`KeyDerivation`
  protocols. It remains the conformance layer — all Appendix E KATs stay here.
- `SEAL` (engine) is the recommended product. README/DocC lead with it; the core is
  documented as "for implementers and vector tooling".

**Access control is the structural mechanism.** Swift's `package` access level
(SE-0386, tools 6.0 — already our floor) makes declarations visible across targets
within the package but invisible to consumers:

| Core surface | Access after split |
|---|---|
| Types, suite registry, schedule derivation, commitment verify, AAD builders, `derivedNonce`, accumulator/snapshot math | `public` (granular API) |
| `Segment.encryptRandom(... nonce:)` (caller-supplied nonce), `Segment.encryptDerivedUnmetered` | `package` — reachable by SEAL and by the package's own test targets (pinned-nonce KATs), not by consumers |
| `PayloadEncryptor` | deleted from core when the SEAL writer lands (Stage B); its metering logic moves inside the writer. It stays public through Stage A so the package never ships without a sanctioned random-mode encrypt path |

Decrypt statics stay `public` in core (no misuse hazard), as do the F1–F6 typed-error
guards — they become defense-in-depth beneath the engine.

## 2. SEAL engine design (spec-shaped)

### 2.1 Configuration — §4.10.2 profiles pin the tuple

```swift
public enum SEALProfile { case readOnly    // SEAL-RO-v1
                          case readWrite } // SEAL-RW-v1

public struct SEALConfiguration {
    public init(
        profile: SEALProfile,
        aeadID: UInt16, kdfID: UInt16,
        segmentMax: UInt32 = 65536,
        epochLength: UInt8 = 0
    ) throws
}
```

- **`nonce_mode` is not a parameter.** It is derived from `(profile, AEAD)` per the
  spec: RO ⇒ derived (any AEAD — write-once keeps each nonce unique); RW ⇒ random,
  or derived when the AEAD is MRAE (the Table-9 per-AEAD default). F6's mode-mixing
  guard becomes structurally unreachable.
- **`snap_id` is not a parameter either.** Table 13 (transcribed in `NOTES.md`) fully
  determines it: RW ⇒ the masked multiset hash, RO ⇒ none. The tuple MUST is now
  *also* enforced in the core (`ScheduleError.invalidProfileTuple`), so the engine
  config is a convenience over a core guarantee, not the sole gate.
- **`commitment_length` is pinned to `Nh`.** The core keeps the parameter for
  interop with truncating writers.
- Init validates everything currently validated by `PayloadSchedule.init` plus the
  profile tuple; the config is otherwise opaque (schedule keys never touchable).
- **Named instantiations (§4.12)**: a `SEALScheme` enum mirroring the spec's named
  table — one-call construction where the scheme fixes profile/segmentMax/snapshot/
  epoch. *Exact tuples must be read from the vendored spec snapshot before
  implementation (see §5 prerequisite).*

### 2.2 Lifecycle objects — §3.2/3.3 Table 1, §4.9 procedures

**Write path (`StartEnc` → `EncSeg`* → snapshot):**

```swift
let writer = try config.startEncryption(cek: cek, globalAssociatedData: g)
                                                      // salt generated internally
let seg    = try writer.encrypt(plaintext,
                 at: SegmentPosition(index: 0, isFinal: true),
                 associatedData: [])                   // -> SealedSegment
let object = try writer.finalize()                     // -> SealedObjectHeader + snapshot + state
```

- `startEncryption` generates the 32-octet salt internally (via
  `SystemRandomNumberGenerator`) — the salt-uniqueness host obligation (F7) becomes
  construction. A `SEAL.generateCEK()` helper vends a zeroizing CEK. The optional
  `globalAssociatedData` is the raAE `G` (§3.2/§4.6): bound into the commitment,
  never stored, re-supplied by the decryptor.
- `SealedSegment { position, nonceMetadata: [UInt8]?, ciphertext }` — nonce metadata
  present only in random mode (derived mode stores nothing, recomputed on open). **No
  nonce parameters anywhere** (F5); a later stage upgrades generation to the hedged
  plaintext-bound construction (spec Appendix D / RFC 8937).
- The writer maintains the snapshot accumulator internally (`add(i, tag)` per §4.9.1.1)
  and meters the §5.9 budget with **hard** caps (no warn-mode bypass; F4 semantics).
  RO writer: write-once is structural — a second encrypt at a written index is an
  error, and the RO writer type has no rewrite operation at all.
- `finalize()` emits `SealedObjectHeader { salt, commitment, payloadInfo }`, the
  masked snapshot value, and a `PersistableState` (budget counters + written-index
  summary) for §5.9.5 freeze/resume. The raw accumulator never crosses the boundary.

**Read path (`StartDec` → `SnapVerify` → `DecSeg`*):**

```swift
let reader = try config.startDecryption(cek: cek, header: header, globalAssociatedData: g)
                                                                    // commitment verified — only constructor
try reader.verify(snapshot: snapshot, segments: presentTags)        // SnapVerify + highest-index-final check
let pt     = try reader.decrypt(seg, associatedData: [])
```

- The *only* way to obtain a reader verifies the commitment (§4.6) — the current
  "documented MUST" becomes the type system. `verify(snapshot:)` implements the full
  §4.9.1.2 read check including the finality rule ("reject if the highest-indexed
  segment lacks is_final = 1"), which nothing in the current package enforces.
  Under RO (`snap_id = none`) `verifySnapshot` refuses with a typed error
  (`noSnapshotAuthenticator` — one reader type, not two), but the finality rule
  still applies — §4.10.2: "truncation detection rests on the finality bit alone" —
  so `verifyFinality(positions:)` checks the claimed positions in both profiles
  (cryptographically confirmed when the final segment is decrypted).
- Freshness/rollback remains a host obligation (spec: snapshot proves set integrity,
  not recency) — documented on `verify`, unchanged from F7.

**Rewrite path (RW only, `RewriteSeg` §4.9.2):**

```swift
var rw = try config.resumeWriting(cek: cek, header: header,
             snapshot: snapshot, segments: presentTags, state: persisted)
let (newSeg, newSnapshot) = try rw.rewrite(plaintext, at: pos, replacing: oldSeg)
```

- `resumeWriting` is only constructible for `.readWrite` — the F4 gate becomes a
  missing method rather than a runtime error.
- It verifies the presented snapshot first, then **recovers the raw accumulator by
  unmasking internally** (`acc = wrapped_acc XOR mask(n_seg, tag)` — the schedule
  holds `snap_key`, so no raw-acc persistence is ever needed). `rewrite` performs
  RewriteSeg + `remove(i, old_tag)`/`add(i, new_tag)` + re-snapshot as one operation;
  the accumulator API disappears from the consumer's world entirely (F7).

### 2.3 Storage model

The spec delegates serialization to the consuming protocol (§2.1; §4.11 layouts are
informative), and our consumers (message attachments on iOS) store segments in their
own containers. So:

- The engine deals in **values** (`SealedObjectHeader`, `SealedSegment`, snapshot
  bytes); the host owns placement. No io-stream surface.
- A `SEALContainer` convenience (the §4.11 *Linear* layout: header ‖ segments ‖
  snapshot in one `Data`, single-call seal/open of a whole payload) ships as sugar on
  top — stage D, optional. Aligned layouts and armoring: out of scope until a
  consumer needs them.

### 2.4 Index bounds — spec-exact, no engine cap

The engine enforces exactly the spec's bounds: the §4.5.3.2 derived-mode MUST
(`index < 2^63`) lives in the core and propagates through every engine path; random
mode has no architectural index limit. **Noted, not adopted:** some other
implementations cap segment indices at `2^48` as a cross-implementation convention
(overflow headroom, shared accept/reject sets). An earlier revision of this engine
enforced that cap, unevenly — writer/reader checked it, the snapshot-verify and
rewrite paths did not — which is exactly the asymmetry the cap is meant to prevent.
It was dropped in favor of spec-exact behavior; revisit only if ecosystem interop
demands the shared cap, and then apply it on *every* index-accepting path at once.

## 3. Structural-guarantee map (review finding → construction)

| Finding (0.0.1 fix) | Core (stays, defense-in-depth) | SEAL engine (structural) |
|---|---|---|
| F1 segment_max | typed-error guards | writer validates; container chunks |
| F2 index bound | reject ≥ 2^63 (spec MUST) | spec bound only, via core (no engine cap; §2.4) |
| F3 snap_id | registry + Table-13 tuple rejection (core) | `snap_id` not a parameter at all |
| F4 write-once | gate + hard metering | RO writer has no rewrite op; rewriter unconstructible for RO |
| F5 nonce param | metered path owns nonce | no nonce params exist; hedged gen later |
| F6 mode mixing | `nonceModeMismatch` | `nonce_mode` not a parameter |
| F7 salt/acc/replay docs | docs remain | salt generated internally; acc never exposed; finality check in `verify` |
| F8 commitment floor | param kept, documented | pinned to `Nh` |
| Verify-before-decrypt | `startDecrypt` convention | only reader constructor verifies |
| Budgets (§5.9) | — (`PayloadEncryptor` removed) | built into writer, hard caps, persistable state |

## 4. Staging

- **Stage A — split & seams.** Add the `SEAL` target/product (profile type +
  engine caps as first content); demote the raw-nonce encrypt seams in core to
  `package`; core KATs unchanged and byte-exact. `PayloadEncryptor` stays public
  until Stage B so a sanctioned encrypt path always exists. Breaking, changeset
  per move.
- **Stage B — engine core.** `SEALConfiguration` + profile tuple validation,
  writer/reader (write & read paths, snapshot lifecycle, budgets, freeze/resume),
  RO structural write-once; delete `PayloadEncryptor` (absorbed by the writer).
  End-to-end tests: E-vector payloads round-tripped through the engine; profile
  validation matrix; finality-rule negatives.
- **Stage C — RW rewrite + named instantiations.** `resumeWriting`/`rewrite` with
  internal unmasking (pin against E.16.1 rewrite vector); `SEALScheme` from the
  vendored §4.12 table.
- **Stage D — conveniences and hardening (optional; see §6).** Hedged randomness
  (Appendix B), plaintext-bound nonces (Appendix A), linear-layout container,
  extend/truncate, digest-based verify overloads, polish.

## 5. Prerequisite and open spec checks

**Resolved against the vendored snapshot** (`Spec/draft-2026-07-06.html`; see the
Table 13/15 transcriptions in `NOTES.md` and the `G` drift note in `SOURCE.md`):

- §4.10.2 Table 13: RO pins derived + `snap_id 0x0000`; RW requires `0x0001`.
  Enforced in the core (`invalidProfileTuple`); the engine config never exposes the
  choice.
- §4.12 Table 15: five named instantiations (attachment/simple/memory/disk/compact);
  each *binds a serialization layout*, so an engine scheme preset without its layout
  is a parameter preset, not a claimable named instantiation — naming must say so
  until Stage D ships the layout.
- §4.9.1.2 finality rule applies in both profiles (under RO it is the sole
  truncation defense).
- §4.6 `G`: discovered via snapshot-vs-vector diffing, now implemented in the core
  (commitment binds `[...payload_info, G]`; E.2 pinned).

**Resolved (was: "Appendix D hedged-nonce normativity")**: in the vendored snapshot
the constructions live in **Appendix A** (Optional Plaintext-Bound Nonce — explicitly
informative: "Implementations MAY use this construction in place of a fresh CSPRNG
call … under nonce_mode 'random'"; encryptor-only, wire-indistinguishable from random
mode; E.19 component vectors) and **Appendix B** (Optional Hedged Randomness — a
*conditional* SHOULD: "When a long-term symmetric key sk of at least Nh octets is
available to the encryptor, implementations SHOULD mix it into random generation"
per RFC 8937). The engine's API takes no long-term sender key today, so the SHOULD's
condition is unmet and the plain-CSPRNG path is conformant; offering a sender key is
what activates it (§6). Nothing in Stage D is required work.

## 6. Stage D scope (all optional)

- **D1 — Hedged randomness (Appendix B; conditional SHOULD).** Add an optional
  `senderKey` to `startEncryption`; when supplied, derive
  `hedge_key = KDF(protocol_id, "hedge", sk, [], Nh)` and draw the salt and
  random-mode nonces through `HedgedRandom` (RFC 8937 pattern). Supplying the key is
  what triggers the spec's SHOULD; hedging defends weak-CSPRNG output but not
  duplicated CSPRNG state (that is D2's job).
- **D2 — Plaintext-bound nonces (Appendix A; MAY).** Encryptor-only replacement for
  the fresh-CSPRNG draw in random mode (`pt_hash`/`pt-nonce` labels, Table 24),
  defending RNG state duplication (VM snapshots, fork). Wire format unchanged;
  decryption unaffected. Pin against the E.19 component vectors.
- **D3 — Linear-layout container (§4.11.1, reduced immutable form §4.11.4).** A
  single-`Data` seal/open convenience over the engine values. Prerequisite for
  claiming any §4.12 named instantiation, since each row binds a layout; until then
  `SEALScheme` remains a parameter preset.
- **D4 — Extend/truncate (Table 13 RW mutability).** The rewriter covers rewrite
  only; extend appends indices (n_seg grows, snapshot rebinds, finality moves) and
  truncate removes a tail. Both need the finality-shape rules re-derived from the
  spec's extend/truncate text before design.
- **D5 — Digest-based verify/resume overloads.** `verifySnapshot`/`resumeWriting`
  accepting `(position, tag)` pairs instead of full `SealedSegment`s, so verifying a
  large object does not require its ciphertext in memory.
- **D6 — Polish.** Split `SEALError.incompleteSegmentSet` into distinct cases;
  expose `SEALScheme` row parameters publicly; add a rewriter wrong-`G` test;
  deduplicate the internal `xor`/budget helpers against the core; adopt
  swift-docc-plugin (or exclude the catalogs) to silence the two benign
  unhandled-`.docc` build warnings.
