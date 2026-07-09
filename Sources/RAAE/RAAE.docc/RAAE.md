# ``RAAE``

Random-access authenticated encryption (raAE) and the SEAL construction, per
[`draft-sullivan-cfrg-raae`](https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html).

## Overview

SEAL partitions a message into independently encryptable **segments**: any segment can
be encrypted or decrypted on its own, in any order; segments can be rewritten in place;
and an optional snapshot authenticator detects added, dropped, reordered, or modified
segments.

This release ships the verified low-level engine. A typical flow:

```swift
import RAAE

// 1. Describe the message parameters.
let info = PayloadInfo(
    aeadID: 0x0002,   // AES-256-GCM
    segmentMax: 16384,
    kdfID: 0x0001,    // HKDF-SHA-256
    snapID: 0x0001,   // masked multiset hash
    nonceMode: .random,
    epochLength: 1,
    salt: salt)       // 32 random octets, unique per object

// 2. Derive the key schedule from the 32-octet CEK.
let schedule = try PayloadSchedule(
    protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)

// 3. Encrypt a segment (random nonce mode) through the metered encryptor: it
//    generates the nonce, returns it for storage, and tracks the §5.9 budget.
let encryptor = PayloadEncryptor(schedule: schedule)
let pos = SegmentPosition(index: 0, isFinal: true)
let (nonce, ciphertext) = try encryptor.encryptRandom(
    position: pos, associatedData: [], plaintext: plaintext)

// 4. Authenticate the whole set with a snapshot.
let hash = MaskedMultisetHash(schedule: schedule)
let tags = [(index: UInt64(0), tag: Array(ciphertext.suffix(16)))]
let snapshot = hash.snapshotValue(
    segmentCount: 1, accumulator: hash.accumulator(segments: tags))
```

For MLS attachment encryption (`draft-sullivan-mls-attachments`), skip the manual
parameter selection: ``SEALAttachment`` packages the draft's
`SEAL-attachment(aead_id, kdf_id)` named instantiation (§4.12) — write-once profile,
derived nonces, 64 KiB segments, a `salt || commitment` header, and the attachment's
`object_id` bound as the global associated data `G`:

```swift
let suite = SEALAttachment.Suite(mlsCipherSuite: 0x0001)!
let object = try SEALAttachment.encrypt(
    cek: cek,             // 32 octets, derived per object_id on the MLS side
    objectID: objectID,   // the attachment's object_id (bound as G)
    suite: suite,
    plaintext: fileBytes)
let back = try SEALAttachment.decrypt(
    cek: cek, objectID: objectID, suite: suite, object: object)
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
  ``PayloadSchedule/startDecrypt(protocolID:cek:payloadInfo:globalAAD:publishedCommitment:expectedCommitmentLength:)``
  (§4.6) and verify the snapshot before trusting the segment set (§4.9.1.2).
- **Snapshot freshness.** A complete old `(segments, snapshot)` pair verifies — the
  snapshot proves set integrity, not recency. Rollback protection requires the host
  to bind the snapshot to a version, or store it authenticated out of band.
- **Publish only ``MaskedMultisetHash/snapshotValue(segmentCount:accumulator:)``.**
  The raw accumulator (kept for O(1) rewrites) is unmasked internal state; store it
  privately.
- **Persist usage counters.** ``PayloadEncryptor`` meters a single live writer.
  Resuming an object in another process requires seeding
  ``PayloadEncryptor/persistableState`` (§5.9.5); concurrent writers need external
  coordination.

## Topics

### MLS attachments

- ``SEALAttachment``
- ``SEALAttachment/Suite``
- ``SEALAttachment/Layout``

### Message parameters and key schedule

- ``PayloadInfo``
- ``PayloadSchedule``
- ``ProtocolID``

### Per-segment encryption

- ``Segment``
- ``SegmentPosition``

### Safe decryption

- ``PayloadSchedule/startDecrypt(protocolID:cek:payloadInfo:globalAAD:publishedCommitment:expectedCommitmentLength:)``
- ``PayloadSchedule/verifyCommitment(_:)``

### Usage limits

- ``UsageBudget``
- ``PayloadEncryptor``
- ``BudgetPolicy``

### Snapshot authenticator

- ``MaskedMultisetHash``
- ``ConstantTime``

### Cipher suites

- ``SuiteRegistry``
- ``AEAD``
- ``KeyDerivation``
- ``AEADError``
