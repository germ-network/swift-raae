# Normative transcription — KDF layer (Stage 1)

Transcribed from the vendored draft snapshot (see `SOURCE.md`; originally 2026-06-26,
vector numbering updated to the 2026-07-06 refresh). Section numbers refer to that
snapshot and may drift. **This is the authority for the code, not
the plan's prose** (the plan was written from a summary and had label errors — noted
below).

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

Schedule labels (§4.4.3, Table 3) — **note plan said `snap_key`; spec says `acc_key`**:

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

`aead_id` (Table 7), `kdf_id` (Table 8) are `uint16`. Known ids:
- AEAD: `0x0001` AES-128-GCM, `0x0002` AES-256-GCM, `0x0003` ChaCha20-Poly1305,
  `0x0010` AEGIS-128L, `0x0011` AEGIS-256 (+ AES-256-GCM-SIV for MRAE).
  For all Table-7 AEADs: `C_i = ct_i || tag_i`, tag is the final `Nt` octets.
- KDF: `0x0001` HKDF-SHA-256, `0x0002` HKDF-SHA-512, `0x0013` TurboSHAKE-256.
- `snap_id` (Table 9): `0x0000` none, `0x0001` masked multiset hash. Unknown values
  are rejected in `PayloadSchedule.init` (like unknown `aead_id`/`kdf_id`).
- `nonce_mode` (Table 10): `0x00` random, `0x01` derived.

**Table 7 (AEAD) — verified IANA code points, NOT sequential:**
| name | aead_id | Nk | Nn | default mode |
|------|---------|----|----|--------------|
| AES-128-GCM | `0x0001` | 16 | 12 | random |
| AES-256-GCM | `0x0002` | 32 | 12 | random |
| ChaCha20-Poly1305 | `0x001D` | 32 | 12 | random |
| AES-256-GCM-SIV | `0x001F` | 32 | 12 | derived |
| AEGIS-256 | `0x0021` | 32 | 32 | random |

**Table 8 (KDF):** `0x0001` HKDF-SHA-256 (Nh 32), `0x0002` HKDF-SHA-**384** (Nh 48),
`0x0003` HKDF-SHA-512 (Nh 64), `0x0013` TurboSHAKE-256 (Nh 64, one-step).

> ⚠️ The summary-based plan mis-stated these: it had ChaCha at `0x0003` and HKDF-SHA-512
> at `0x0002`. The E.5 ChaCha vector (E.3 in the 2026-06-26 snapshot) caught both.
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

## Payload schedule (§4.5.1) — verified byte-exact against E.1

All keys derive from `CEK` (ikm) with `payload_info` as the KDF `info` list. The
`info` list is the **7 payload_info elements in order**, each framed individually:
`[aead_id(u16), segment_max_be(u32), kdf_id(u16), snap_id(u16), nonce_mode(u8),
epoch_length(u8), salt(32)]`.

```
commitment  = KDF(protocol_id, "commit",      [CEK], payload_info, commit_len)  ; default Nh, min 16
payload_key = KDF(protocol_id, "payload_key", [CEK], payload_info, Nk)
snap_key    = KDF(protocol_id, "acc_key",     [CEK], payload_info, Nh)
nonce_base  = KDF(protocol_id, "nonce_base",  [CEK], payload_info, Nn)           ; derived mode only
```

The draft prints a full KDF trace for the commitment; our Stage-1 KDF reproduces
`prk` and `commitment` exactly, confirming framing + Extract/Expand are correct.

### Segment key via epoch key (§4.5.2)

```
segment_key(i):
    epoch_index = i >> epoch_length
    return KDF(protocol_id, "epoch_key", [payload_key], [uint64(epoch_index)], Nk)
```
`epoch_length = r ∈ [0,63]` (MUST reject ≥ 64); `r = 0` ⇒ per-segment key.

### Segment AAD (§4.4.2, Table 2)

```
segment_aad(i, is_final, A_i):
    random mode:  encode(aad_label, uint64(i), uint8(is_final)[, A_i])   ; A_i appended only if non-empty
    derived mode: ""  if A_i empty, else encode(aad_label, A_i)          ; i/is_final are bound in the nonce
```
`aad_label = "SEAL-DATA"`. Verified: E.1 seg0 aad = `encode("SEAL-DATA", uint64(0), uint8(1))`.

### EncryptSegment / DecryptSegment (§4.8)

`C_i = AEAD.Encrypt(segment_key(i), nonce(i), segment_aad(i,is_final,A_i), P_i)`, split
into `ct_i || tag_i`. Decrypt reverses it; AEAD auth failure ⇒ decryption error.

### Masked multiset hash snapshot (§4.7.4) — verified vs E.1/E.9/E.16.1

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

### Vector constants (Appendix E, informative)

Every block: `protocol_id="SEAL-RW-v1"`, `CEK = 32×0xAA`, `salt = 32×0x04`. Vectors
print ciphertext+tag but not plaintext; tests recover `P_i` by decrypting (the AEAD tag
guarantees `segment_key`/`nonce`/`aad` are all correct), then re-encrypt under the
vector's fixed nonce to pin the ciphertext in both directions.

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
  generation. The pinned-nonce seam (`Segment.encryptRandom(... nonce:)`, and the
  unmetered derived core) is `package`-scoped: reachable by the byte-exact KATs and
  the SEAL engine target, never by consumers (see `Spec/SEAL-ENGINE-PLAN.md`). The `maxEpochKeysLog2` ceiling (§5.9.6) is advisory and not metered.
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
correctness is fully pinned only in Stage 2 against the Appendix E commitment vector;
Stage 1 tests cover framing, HKDF determinism/structure, and AEAD round-trips.
