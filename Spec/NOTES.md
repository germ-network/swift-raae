# Normative transcription — KDF layer (Stage 1)

Transcribed from the draft (see `SOURCE.md`; originally the 2026-06-26 snapshot,
resynced to the published `draft-sullivan-cfrg-raae-02` on 2026-07-13). Section,
table, and vector numbers refer to `-02` and may drift in later revisions. **This is
the authority for the code, not the plan's prose** (the plan was written from a
summary and had label errors — noted below).

## Notation (§2.2)

- `Nk` — AEAD key size (octets)
- `Nn` — AEAD nonce size (octets)
- `Nt` — AEAD tag size (octets)
- `Nh` — KDF hash/PRF output size (octets)
- `uint16(x)` / `uint32(x)` — big-endian fixed-width integer encodings.

## Length-prefixed framing (§4.3)

```
frame(x):
    if len(x) <= 0xFFFE:  return uint16(len(x)) || x
    else:                 return uint16(0xFFFF) || LH(x)

encode(x1, ..., xn) = frame(x1) || ... || frame(xn)
```

- Each field gets a **big-endian 2-octet length prefix**.
- Over-large fields (> 65534 octets) use the escape length `0xFFFF` followed by an
  `Nh`-octet digest `LH(x)` of the field. `LH` invokes the KDF's native primitive
  directly with label `"raAE-LP-v1"`:
  - two-step: `LH(x) = Extract(salt="raAE-LP-v1", ikm=x)` (Nh octets)
  - one-step: `LH(x) = XOF("raAE-LP-v1" || x, Nh)`
- Framing is therefore **parameterized by the KDF** (the over-large path needs the
  hash). Our KDF supplies `LH`; `encode` takes it as a closure.

## KDF(protocol_id, label, ikm, info, L) (§4.3)

`ikm` and `info` are *lists* of byte strings; `...x` spreads each element as its own
`encode` argument. `uint16(L)` is appended as a final field.

```
two-step (HKDF):
  extract_input = encode(protocol_id, label, ...ikm)
  prk           = Extract(salt=protocol_id, ikm=extract_input)
  expand_info   = encode(protocol_id, label, ...info, uint16(L))
  return          Expand(prk, expand_info, L)

one-step (XOF):
  M = encode(protocol_id, label, encode(...ikm), encode(...info), uint16(L))
  return XOF(M, L)
```

## Constants / labels

Protocol IDs (§4.10.2): immutable `"SEAL-RO-v1"`, mutable `"SEAL-RW-v1"`.

Schedule labels (§4.4.3, Table 4) — **note plan said `snap_key`; spec says `acc_key`**:

| Role        | Label          |
|-------------|----------------|
| Commitment  | `"commit"`     |
| Payload key | `"payload_key"`|
| Snapshot/acc key | `"acc_key"` |
| Nonce base  | `"nonce_base"` |
| Epoch key   | `"epoch_key"`  |

Masked multiset hash labels (§4.7.4): `"acc_contrib"`, `"snapshot_tag"`,
`"snapshot_mask"`.

Labels + protocol IDs are ASCII bytes; within `encode` they are `frame()`d like any
other field (no separate extra prefix).

## Suite registry

`aead_id` (Table 10), `kdf_id` (Table 11) are `uint16`. For all Table-10 AEADs:
`C_i = ct_i || tag_i`, tag is the final `Nt` octets.
- `snap_id` (Table 12): `0x0000` none, `0x0001` masked multiset hash, `0x0002`
  digest transcript (§4.7.5), `0x0003` epoch digest tree (§4.7.6). This build
  implements `0x0000`/`0x0001` only; every other value — including the two
  `-02`-defined ones — is rejected in `PayloadSchedule.init` (like unknown
  `aead_id`/`kdf_id`: the field is committed into the KDF, so accepting a value the
  build cannot honor would bind parameters it cannot verify).
- `nonce_mode` (Table 13): `0x00` random, `0x01` derived.

**Table 10 (AEAD) — verified IANA code points, NOT sequential:**
| name | aead_id | Nk | Nn | default mode | epoch_length |
|------|---------|----|----|--------------|--------------|
| AES-128-GCM | `0x0001` | 16 | 12 | random | 0–63 (default 0) |
| AES-256-GCM | `0x0002` | 32 | 12 | random | 0–63 (default 0) |
| ChaCha20-Poly1305 | `0x001D` | 32 | 12 | random | 0–63 (default 0) |
| AES-256-GCM-SIV | `0x001F` | 32 | 12 | derived | 0–63 (default 0) |
| AEGIS-256 | `0x0021` | 32 | 32 | random | 63 (flat key) |
| AEGIS-256X2 | `0x0024` | 32 | 32 | random | 63 (flat key) |

(`-02` added AEGIS-256X2 and the per-AEAD `epoch_length` column; AEGIS is Stage 4.)

**Table 11 (KDF):** `0x0001` HKDF-SHA-256 (Nh 32), `0x0002` HKDF-SHA-**384** (Nh 48),
`0x0003` HKDF-SHA-512 (Nh 64), `0x0013` TurboSHAKE-256 (Nh 64, one-step; specified
in RFC 9861, selected for the HPKE KDF registry by `draft-ietf-hpke-pq`).

> ⚠️ The summary-based plan mis-stated these: it had ChaCha at `0x0003` and HKDF-SHA-512
> at `0x0002`. The F.5 ChaCha vector (E.3 in the 2026-06-26 snapshot) caught both.
> Always take ids from this table.

### Derived nonce (§4.5.3)

`nonce(i) = nonce_base XOR ((i<<1)|is_final)`, where the value is encoded big-endian and
XORed into the **low 8 octets** of the `Nn`-octet `nonce_base` (requires `Nn ≥ 8`).
`(i<<1)|is_final` must fit 64 bits, so derived mode rejects `i ≥ 2^63` (a larger index
would silently drop its top bit and alias the nonce of `i − 2^63` — never under the same
epoch key for `r ≤ 63`, but the injectivity assumption should not rest on that).

## payload_info wire layout (§4 / Table refs)

```
payload_info = [ aead_id(uint16) | segment_max(uint32) | kdf_id(uint16) |
                 snap_id(uint16) | nonce_mode(uint8) | epoch_length(uint8) |
                 salt(32 octets) ]
```
The KDF applies `frame` to each element of this list when it is used as a KDF input.
`segment_max` is a power of two ≥ 4096; `epoch_length` is `r ∈ [0,63]`.

## Payload schedule (§4.5.1) — verified byte-exact against F.1

All keys derive from `CEK` (ikm) with `payload_info` as the KDF `info` list. The
`info` list is the **7 payload_info elements in order**, each framed individually:
`[aead_id(u16), segment_max_be(u32), kdf_id(u16), snap_id(u16), nonce_mode(u8),
epoch_length(u8), salt(32)]`.

```
commitment  = KDF(protocol_id, "commit",      [CEK], [...payload_info, G], commit_len)  ; default Nh, min 16
payload_key = KDF(protocol_id, "payload_key", [CEK], payload_info, Nk)
snap_key    = KDF(protocol_id, "acc_key",     [CEK], payload_info, Nh)
nonce_base  = KDF(protocol_id, "nonce_base",  [CEK], payload_info, Nn)           ; derived mode only
```

The draft prints a full KDF trace for the commitment (F.1); our Stage-1 KDF
reproduces its `prk` and `commitment` (`47ea0ec7…`) exactly, confirming framing +
Extract/Expand are correct. (Historical: the pre-`-01` snapshots printed the *pre-G*
commitment `020e115b…` — the `commit` label's `info` since gained the framed empty-G
element, while `prk`, which is `info`-independent, never changed.)

### Global associated data G (§4.2.4, §4.5.1, §4.6)

`G` is the `StartEnc`/`StartDec` global associated data: whole-message application
context (for MLS attachments, the `object_id`). It binds into the **commitment
only**, framed as the last element of the commit `info` — `payload_key` /
`acc_key` / `nonce_base` never take it. `G` is never stored; the decryptor
re-supplies it, and a wrong or missing value fails as `commitmentMismatch`, exactly
like a wrong CEK.

> **Empty-G convention (per the published draft, `-01`/`-02` identical).** `G` is
> **always** the last element of the commit `info`, including the empty default —
> the draft frames it as "one zero-length element, so every commitment derivation
> includes it." The vendored Appendix F corpus carries the commitment values this
> produces (F.1 `47ea0ec7…`; the pre-G `020e115b…` is retired). `GlobalAADTests`
> pins the empty default against Appendix F.1 and non-empty G against Appendix F.2
> (`G="raae-demo-g"` → `d8eedb1f…`). Only the commitment changed in the empty-G
> resync — `payload_key` / `acc_key` / `nonce_base` and every ciphertext are
> byte-identical, and every non-empty G was already byte-identical under the prior
> (empty-G-omitted) convention, so the SEAL-simple KATs (whose `G = object_id` is
> always non-empty) were unaffected.
>
> ⚠️ The commitment is a stored, wire-visible value (e.g. the SEAL-simple header is
> `salt || commitment`), so that resync changed what empty-G objects verify against.
> The `germ-network/mls-rs` companion must switch conventions in lockstep for
> empty-G objects; non-empty-G objects (all MLS attachment objects) interoperate
> across both conventions.

### Segment key via epoch key (§4.5.2)

```
segment_key(i):
    epoch_index = i >> epoch_length
    return KDF(protocol_id, "epoch_key", [payload_key], [uint64(epoch_index)], Nk)
```
`epoch_length = r ∈ [0,63]` (MUST reject ≥ 64); `r = 0` ⇒ per-segment key.

### Segment AAD (§4.4.2, Table 3)

```
segment_aad(i, is_final, A_i):
    random mode:  encode(aad_label, uint64(i), uint8(is_final)[, A_i])   ; A_i appended only if non-empty
    derived mode: ""  if A_i empty, else encode(aad_label, A_i)          ; i/is_final are bound in the nonce
```
`aad_label = "SEAL-DATA"`. Verified: F.1 seg0 aad = `encode("SEAL-DATA", uint64(0), uint8(1))`.

### EncryptSegment / DecryptSegment (§4.8)

`C_i = AEAD.Encrypt(segment_key(i), nonce(i), segment_aad(i,is_final,A_i), P_i)`, split
into `ct_i || tag_i`. Decrypt reverses it; AEAD auth failure ⇒ decryption error.

### Masked multiset hash snapshot (§4.7.4) — verified vs F.1/F.9/F.16.1

```
contrib(i)   = KDF(protocol_id, "acc_contrib",  [snap_key], [uint64(i), tag(i)], Nh)
acc          = contrib(0) XOR contrib(1) XOR ...                 ; 0^Nh for the empty set
snapshot_tag = KDF(protocol_id, "snapshot_tag", [snap_key], [uint64(n_seg), acc], Nh)
mask         = KDF(protocol_id, "snapshot_mask",[snap_key], [uint64(n_seg), snapshot_tag], Nh)
snapshot     = (acc XOR mask) || snapshot_tag                    ; wrapped_acc || snapshot_tag
```
- `tag(i)` is the segment's AEAD tag (the final `Nt` octets). Finality is bound through
  `tag(i)` (it's an AEAD input in both nonce modes), so `contrib` needs no explicit
  is_final term.
- XOR makes `acc` order-independent and self-inverse → **rewrite is O(1)**:
  `acc' = acc XOR contrib(i, old_tag) XOR contrib(i, new_tag)`, `n_seg` unchanged.
- `n_seg` is NOT stored in the snapshot; the verifier supplies it (the count of segments
  present). **SnapVerify** recomputes the snapshot over the present segments and compares
  constant-time; it accepts reordering but rejects add/drop/modify.
- Empty object: `acc = 0^Nh`, `snapshot = mask || snapshot_tag` over zero segments.

### Vector constants (Appendix F, informative)

Every block: `CEK = 32×0xAA`, `salt = 32×0x04`; `protocol_id="SEAL-RW-v1"` for the
RW corpus and `"SEAL-RO-v1"` for F.23. Vectors print ciphertext+tag but not
plaintext; tests recover `P_i` by decrypting (the AEAD tag guarantees
`segment_key`/`nonce`/`aad` are all correct), then re-encrypt under the vector's
fixed nonce to pin the ciphertext in both directions.

## SEAL-simple named instantiation (§4.12) — MLS attachments

`SEAL-simple(aead_id, kdf_id)` per `draft-sullivan-cfrg-raae-02` Table 16 (named
`SEAL-attachment` in `-01`), the scheme `draft-sullivan-mls-attachments` (`-00`,
2026-07-06) consumes:

- Profile `SEAL-RO-v1`, `segment_max` 65536, `nonce_mode` derived,
  `epoch_length` 32, `snap_id` **0x0000** (no snapshot authenticator),
  `commitment_length = Nh`, fresh 32-octet salt per object. Any AEAD is admitted
  (write-once licenses derived + non-MRAE via §4.5.3.2's discipline).
- Linear layout, reduced immutable form (§4.11.4): no stored nonces, no snapshot.

  ```
  object    = salt(32) || commitment(Nh) || segment(0) || ... || segment(n-1)
  segment   = ciphertext || tag(16)
  offset(i) = (32 + Nh) + i * (65536 + 16)
  ```

  Every non-final segment is exactly 65536 plaintext octets; only the final may be
  shorter; a valid object has ≥ 1 segment.
- MLS binding (`draft-sullivan-mls-attachments`): `aead_id`/`kdf_id` are the IANA
  (RFC 5116 / RFC 9180) code points of the group's MLS cipher suite; `G =
  object_id` (raw octets, non-empty, ≤ 255 — a receiver MUST reject empty);
  per-segment `A_i` is empty on both `EncSeg`/`DecSeg`; the 32-octet CEK is derived
  MLS-side (`SafeExportSecret(ComponentID)` → `ExpandWithLabel(..., "attachment",
  object_id, 32)`). Whole-object integrity = open every segment (index `n-1` as
  final) against the *authenticated* length in the object reference.

> **Naming (resolved in `-02`).** `-01` called this instantiation
> `SEAL-attachment`; `-02` renamed it `SEAL-simple` and rebound `SEAL-attachment`
> to a *different* new write-once instantiation (epoch digest tree `snap_id`
> 0x0003, aligned layout with an epoch-heads region, `epoch_length` 10 — not
> implemented here; nor is `SEAL-attachment-small`, digest transcript `snap_id`
> 0x0002). The attachments draft (`-00`) references the linear-layout scheme, i.e.
> `SEAL-simple`; re-check its wording when it revs against `-02`.

`SEALSimple` packages all of the above (suite mapping, layout, metered write-once
`Writer`, commitment-verified `Reader`, one-shot encrypt/decrypt);
`SEALSimpleTests.f23PublishedVectorRoundTrips` pins the instantiation end-to-end
against the published Appendix F.23 vector (empty `G`, core APIs), and
`SEALSimpleTests.attachmentScheduleKAT` pins the MLS-bound schedule (non-empty
`G = object_id`) against an independent implementation.

## Implementation safety rails (beyond the spec text)

- **Segment AAD framing uses the real `LH`.** `Segment.aad*Mode` takes the message KDF so
  over-large `A_i` (> 65534 octets) frames to `0xFFFF || LH(A_i)`, not a stub — otherwise
  distinct large associated-data values would collide.
- **Derived nonce mode requires an MRAE AEAD under rewritable profiles.** A rewrite
  reuses a segment's fixed nonce, so `PayloadSchedule.init` rejects
  `nonce_mode = derived` with a non-MRAE AEAD — except under `SEAL-RO-v1`
  (`ProtocolID.immutable`), the write-once profile, where §4.5.3.2 permits the pairing
  because each segment is encrypted exactly once. Unknown protocol IDs are treated as
  rewritable (strict). The write-once non-MRAE pairing is only encryptable through
  `PayloadEncryptor` (per-segment budget = one encryption, per-epoch-key budget = the
  epoch's `2^r` indices; the per-segment cap hard-stops under both `enforce` and
  `warn`) — the unmetered `Segment.encryptDerived` static refuses it with
  `writeOnceRequiresMeteredEncryptor`, since an unmetered rewrite would reuse the
  segment's fixed nonce. Decryption is ungated. Cross-process/multi-writer discipline
  (seeding counters via `persistableState`) remains the host's obligation.
- **Named-profile `(nonce_mode, snap_id)` tuples are enforced** (§4.10.2 Table 14:
  "An encryptor MUST set payload_info to a (nonce_mode, snap_id) tuple that is
  valid for its protocol_id, and a decryptor MUST reject any object whose tuple is
  not"). Of this build's authenticators: `SEAL-RW-v1` requires `snap_id = 0x0001`
  (the `-02` table also admits 0x0002/0x0003, which are rejected earlier as
  unsupported) and `SEAL-RO-v1` requires `nonce_mode = derived` with
  `snap_id = 0x0000` (likewise 0x0002/0x0003 in `-02`). Off-profile tuples throw
  `invalidProfileTuple` from `PayloadSchedule.init` — the decrypt-side MUST flows
  through `startDecrypt`, which uses the same initializer. Unknown protocol IDs
  define their own tuples and are unconstrained (only the MRAE gate applies).
- **CEK length is fixed at 32 octets** and validated in `PayloadSchedule.init`.
- **`nonce_mode` is enforced on every segment path.** `Segment.encrypt/decryptRandom`
  require a random-mode schedule and `encrypt/decryptDerived` a derived-mode one
  (`nonceModeMismatch`); the mode is committed into the key schedule, so mixing modes
  under one schedule would emit objects that contradict their `payload_info`.
- **`segment_max` is enforced on every segment path.** `Segment.encrypt*` rejects
  plaintexts longer than `segment_max`, and `Segment.decrypt*` rejects `ct||tag` whose
  implied plaintext (`len − Nt`) exceeds it, before any AEAD work. The §5.9.7.4
  per-segment budget divides by the `segment_max` block count `L`, so an oversized
  segment would silently weaken the metered data-volume bound while appearing metered.
- **Verify-before-decrypt is the recommended/safe path** (§4.6, §4.9.1.2), enforced by
  convention (a documented MUST), not by the type system — the public `init` can still
  build an unverified schedule. `PayloadSchedule.startDecrypt(...)` re-derives at the
  published commitment length and constant-time-verifies it before returning a schedule;
  `verifyCommitment(_:)` is the standalone check. A mismatch throws
  `CommitmentError.commitmentMismatch` and the caller MUST abandon decryption (dropping the
  rejected schedule scrubs its zeroizing keys, meeting the §4.6 SHOULD).
- **Commitment length: keep the default `Nh`.** The §4.6 floor of 16 octets bounds
  the key-committing property at ~2^64 (birthday on the truncated output) against
  multi-key / invisible-salamander-style adversaries. The default full-`Nh`
  commitment is the recommendation; the floor exists for interop, not as a target.
- **Derived keys are not on the public API** (§5.8): `payloadKey`/`snapKey`/`nonceBase`
  and per-segment keys are internal and held as zeroizing `SymmetricKey` (scrubbed when
  the last reference is released). `AEAD.seal/open` take `SymmetricKey`. Honest limit: each
  derivation transiently materializes secret ikm in `[UInt8]` (the framing `extract_input`,
  and `payload_key`/`snap_key`/`nonce_base` when fed as ikm), and the caller-owned CEK plus
  any register/stack copies are not scrubbable — we bound the *long-lived* secret to one
  zeroizing buffer, not zero copies.
- **Usage budgets (§5.9)** are exposed via `PayloadSchedule.usageBudget(...)` (log2
  bounds) and enforced opt-in by `PayloadEncryptor` (warn/enforce), which meters
  per-epoch-key (and, derived, per-segment) encryptions and delegates to the byte-exact
  `Segment` statics. The metered random-mode path generates its own nonce and returns
  it — the §5.9.7.1 budget assumes uniformly random nonces, so the meter must own
  generation; pinned nonces (vectors) go through the unmetered `Segment` static. The `maxEpochKeysLog2` ceiling (§5.9.6) is advisory and not metered.
  Cross-process accounting (snapshot via `persistableState`, restore via `seed`) and the
  decrypt-side forgery bound are the host's responsibility.
- **Host obligations are documented on the DocC landing page** (and on the relevant
  symbols): unique `(CEK, salt)` per object (shared schedules make objects mutually
  substitutable), snapshot freshness/rollback (an old `(segments, snapshot)` pair
  replays — SnapVerify proves set integrity, not recency), publish only the masked
  `snapshotValue` (never the raw accumulator), and cross-process budget persistence.

## Stage-1 scope

Two-step HKDF KDFs + AES-256-GCM / ChaCha20-Poly1305 AEADs via swift-crypto, framing,
and the suite registry. One-step XOF (TurboSHAKE) and AEGIS land in Stage 4. KDF
correctness is fully pinned only in Stage 2 against the Appendix F commitment vector;
Stage 1 tests cover framing, HKDF determinism/structure, and AEAD round-trips.
