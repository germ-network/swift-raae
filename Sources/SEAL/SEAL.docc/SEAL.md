# ``SEAL``

The high-level engine for random-access authenticated encryption, per
[`draft-sullivan-cfrg-raae`](https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html)
— the recommended product of this package.

## Overview

The engine exposes the spec's lifecycle API (§3.2–3.3: `StartEnc` / `EncSeg` /
`StartDec` / `DecSeg` / `RewriteSeg` / `SnapVerify`) and owns every sharp edge the
granular `RAAE` core leaves to its caller: nonce and salt generation, `nonce_mode`
and `snap_id` selection (pinned by profile, §4.10.2), the §5.9 usage budgets (hard
caps), snapshot accounting (the raw accumulator never crosses the API), and
verify-before-decrypt (the only reader constructor checks the commitment).

```swift
import SEAL

// One configuration per suite — or use a §4.12 named-instantiation preset.
let config = try SEALConfiguration(
    profile: .readWrite,
    aeadID: 0x0002,   // AES-256-GCM
    kdfID: 0x0001,    // HKDF-SHA-256
    segmentMax: 16384)

// Author: the writer generates the salt and nonces, meters the budgets,
// and maintains the snapshot internally.
let cek = SEALConfiguration.generateCEK()
let writer = try config.startEncryption(cek: cek)
let segment = try writer.encrypt(
    plaintext, at: SegmentPosition(index: 0, isFinal: true))
let object = try writer.finalize()

// Read: the constructor verifies the commitment before anything decrypts.
let reader = try config.startDecryption(cek: cek, header: object.header)
try reader.verifySnapshot(object.snapshot!, segments: [segment])
let back = try reader.decrypt(segment)

// Rewrite in place (SEAL-RW-v1 only): resume verifies the full read path first.
let rewriter = try config.resumeWriting(
    cek: cek, header: object.header, snapshot: object.snapshot!,
    segments: [segment], usageState: object.usageState)
let (replacement, newSnapshot) = try rewriter.rewrite(newPlaintext, replacing: segment)
```

> Warning: Pre-release, tracking an early individual Internet-Draft. The API is
> unstable and the implementation is unaudited — not for production use.

## Host obligations

The engine authenticates what it is given; a few properties only the host can supply:

- **Store the CEK safely; one object per CEK+salt schedule.** The engine generates a
  fresh salt per object, so one CEK MAY seal many objects — but the CEK itself is
  the root secret, returned as a plain `[UInt8]` (not zeroizing).
- **Manage `G` out of band.** The global associated data (§4.6) is bound into the
  commitment and never stored; the decryptor must re-supply the exact value, and a
  wrong `G` fails like a wrong key.
- **Snapshot freshness.** ``SEALReader/verifySnapshot(_:segments:)`` proves set
  integrity, not recency — a complete old `(segments, snapshot)` pair replays. Bind
  the snapshot to a version, or store it authenticated out of band.
- **Persist ``SEALUsageState`` for rewritable objects.** Budgets MUST survive a
  freeze (§5.9.5); ``SEALConfiguration/resumeWriting(cek:header:snapshot:segments:usageState:globalAssociatedData:)``
  requires the counters back, and losing them means the object stays frozen. There
  is no mid-authoring resume: author each object in one session.
- **Know when content is expected.** Under `SEAL-RO-v1` no snapshot runs, so
  truncation-to-empty is indistinguishable from a legitimately empty object
  (§4.11.1); whole-object integrity needs `SEAL-RW-v1` or a layer above.
- **Own serialization.** The engine deals in values (``SealedObjectHeader``,
  ``SealedSegment``, snapshot bytes); placement is the consuming protocol's job
  (§2.1). The §4.11 layouts are informative patterns, and a §4.12 named
  instantiation is only claimable together with its bound layout.

## Topics

### Configuration

- ``SEALProfile``
- ``SEALScheme``
- ``SEALConfiguration``

### Authoring

- ``SEALWriter``
- ``SealedObject``
- ``SEALUsageState``

### Reading

- ``SEALReader``

### Rewriting

- ``SEALRewriter``

### Stored values

- ``SealedObjectHeader``
- ``SealedSegment``

### Errors

- ``SEALError``
