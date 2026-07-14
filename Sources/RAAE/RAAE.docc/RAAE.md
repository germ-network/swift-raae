# ``RAAE``

Random-access authenticated encryption (raAE) and the SEAL construction, per
[`draft-sullivan-cfrg-raae`](https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html).

## Overview

SEAL partitions a message into independently encryptable **segments**: any segment can
be encrypted or decrypted on its own, in any order; segments can be rewritten in place;
and an optional snapshot authenticator detects added, dropped, reordered, or modified
segments.

This module is the granular **core** — the byte-exact conformance layer for
implementers and vector tooling. Most consumers want the **SEAL** product instead
(`import SEAL`): its engine owns salt/nonce generation, budgets, snapshot accounting,
and verify-before-decrypt, so the sharp edges below never reach application code.

A decrypt-side flow at this layer (encryption goes through the SEAL writer):

```swift
import RAAE

// 1. The message parameters and commitment arrive with the stored object.
let info = PayloadInfo(
    aeadID: 0x0002,   // AES-256-GCM
    segmentMax: 16384,
    kdfID: 0x0001,    // HKDF-SHA-256
    snapID: 0x0001,   // masked multiset hash (required under SEAL-RW-v1)
    nonceMode: .random,
    epochLength: 1,
    salt: salt)       // the object's 32-octet salt

// 2. Re-derive the schedule and verify the commitment BEFORE any decryption.
let schedule = try PayloadSchedule.startDecrypt(
    protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
    publishedCommitment: storedCommitment)

// 3. Verify the snapshot over the present segments, then open one.
let hash = MaskedMultisetHash(schedule: schedule)
guard hash.verify(snapshot: storedSnapshot, segments: presentTags) else { throw ... }
let plaintext = try Segment.decryptRandom(
    schedule: schedule, position: SegmentPosition(index: 0, isFinal: true),
    associatedData: [], nonce: storedNonce, ciphertext: storedCiphertext)
```

> Warning: Pre-release, tracking an early individual Internet-Draft. The API is
> unstable and the implementation is unaudited — not for production use.

## Host obligations

The engine authenticates what it is given; several properties can only be provided by
the host storing the object:

- **Unique `(CEK, salt)` per object.** Two objects sharing a CEK and `payload_info`
  (salt included) share their entire key schedule: segments — or the whole object —
  become mutually substitutable, with valid commitments and snapshots. Generate a
  fresh random 32-octet salt (or a fresh CEK) for every object.
- **Verify before decrypting.** Obtain decrypt-side schedules via
  ``PayloadSchedule/startDecrypt(protocolID:cek:payloadInfo:publishedCommitment:expectedCommitmentLength:globalAssociatedData:)``
  (§4.6) and verify the snapshot before trusting the segment set (§4.9.1.2).
- **Snapshot freshness.** A complete old `(segments, snapshot)` pair verifies — the
  snapshot proves set integrity, not recency. Rollback protection requires the host
  to bind the snapshot to a version, or store it authenticated out of band.
- **Publish only ``MaskedMultisetHash/snapshotValue(segmentCount:accumulator:)``.**
  The raw accumulator (kept for O(1) rewrites) is unmasked internal state; store it
  privately.
- **Track usage budgets when driving the core directly.** ``UsageBudget`` states the
  §5.9 bounds; the SEAL writer meters them with hard caps for a single live writer,
  and cross-process accounting (§5.9.5) plus concurrent-writer coordination remain
  the host's job.

## Topics

### Message parameters and key schedule

- ``PayloadInfo``
- ``PayloadSchedule``
- ``ProtocolID``

### Per-segment encryption

- ``Segment``
- ``SegmentPosition``

### Safe decryption

- ``PayloadSchedule/startDecrypt(protocolID:cek:payloadInfo:publishedCommitment:expectedCommitmentLength:globalAssociatedData:)``
- ``PayloadSchedule/verifyCommitment(_:)``

### Usage limits

- ``UsageBudget``

### Snapshot authenticator

- ``MaskedMultisetHash``
- ``ConstantTime``

### Cipher suites

- ``SuiteRegistry``
- ``AEAD``
- ``KeyDerivation``
- ``AEADError``
