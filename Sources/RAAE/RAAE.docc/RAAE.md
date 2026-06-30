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
    salt: salt)       // 32 random octets

// 2. Derive the key schedule from the 32-octet CEK.
let schedule = try PayloadSchedule(
    protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)

// 3. Encrypt a segment (random nonce mode).
let pos = SegmentPosition(index: 0, isFinal: true)
let nonce = Segment.freshNonce(for: schedule.aead)
let (_, ciphertext) = try Segment.encryptRandom(
    schedule: schedule, position: pos, associatedData: [],
    plaintext: plaintext, nonce: nonce)

// 4. Authenticate the whole set with a snapshot.
let hash = MaskedMultisetHash(schedule: schedule)
let tags = [(index: UInt64(0), tag: Array(ciphertext.suffix(16)))]
let snapshot = hash.snapshotValue(
    segmentCount: 1, accumulator: hash.accumulator(segments: tags))
```

> Warning: Pre-release, tracking an early individual Internet-Draft. The API is
> unstable and the implementation is unaudited — not for production use.

## Topics

### Message parameters and key schedule

- ``PayloadInfo``
- ``PayloadSchedule``
- ``ProtocolID``

### Per-segment encryption

- ``Segment``
- ``SegmentPosition``

### Safe decryption

- ``PayloadSchedule/startDecrypt(protocolID:cek:payloadInfo:publishedCommitment:)``
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
