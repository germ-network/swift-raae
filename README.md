# swift-raae

A Swift implementation of **random-access authenticated encryption (raAE)** and the
**SEAL** construction (Segmented Encryption and Authentication Layer), per the IETF
draft [`draft-sullivan-cfrg-raae`](https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html).

> **Status: early / pre-release.** Stage 0 scaffolding only — no cryptographic
> functionality yet. The target draft is an individual Internet-Draft (Informational,
> not CFRG-adopted) and is expected to change; see [`Spec/SOURCE.md`](Spec/SOURCE.md)
> for the pinned snapshot. **Do not use for anything real yet.**

## What is raAE / SEAL?

raAE partitions a message into independently encryptable/decryptable **segments**,
enabling:

- **Random-access** encrypt/decrypt of individual segments without touching the whole
  object, in any order and in parallel.
- **Per-segment authenticity** via an AEAD tag on each segment.
- **In-place segment rewrites** with snapshot authentication to detect tampering.
- **Whole-object integrity** via an optional snapshot authenticator (added/dropped/
  reordered/modified segments are detected).

SEAL realises raAE from a parameterized KDF key schedule, a per-segment AEAD, a
commitment binding the key + parameters, and a masked-multiset-hash snapshot.

## Design

The package is structured to mirror the draft's own parameterization over a suite
table: pluggable `AEAD` and `KDF` protocols, with **[swift-crypto](https://github.com/apple/swift-crypto)**
as the default cross-platform backend (AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA256/512).
Exotic suites (AEGIS, TurboSHAKE, AES-256-GCM-SIV) slot in behind the same protocols
in a later stage.

Platforms: macOS, iOS, and Linux (via swift-crypto).

## Usage

Two products ship from this package: **`SEAL`** — the high-level engine most
consumers want — and **`RAAE`** — the granular byte-exact core it is built on, for
implementers and vector tooling.

```swift
import SEAL

// One configuration per suite: nonce mode and snapshot follow the profile (§4.10.2).
let config = try SEALConfiguration(
    profile: .readWrite,
    aeadID: 0x0002,   // AES-256-GCM
    kdfID: 0x0001,    // HKDF-SHA-256
    segmentMax: 16384)

// Author: the writer generates the salt and nonces, meters the §5.9 budgets,
// and maintains the snapshot internally.
let cek = SEALConfiguration.generateCEK()
let writer = try config.startEncryption(cek: cek)
let segment = try writer.encrypt(
    plaintext, at: SegmentPosition(index: 0, isFinal: true))
let object = try writer.finalize()   // header + snapshot to store with the segments

// Read: the only reader constructor verifies the commitment first (§4.6).
let reader = try config.startDecryption(cek: cek, header: object.header)
try reader.verifySnapshot(object.snapshot!, segments: [segment])
let back = try reader.decrypt(segment)
```

## Building

```sh
swift build
swift test
```

## Implementation status

| Stage | Scope | Status |
|-------|-------|--------|
| 0 | Repo bootstrap, package scaffold, CI | ✅ |
| 1 | AEAD/KDF protocols, KDF framing, swift-crypto backends | ✅ |
| 2a | Key schedule, commitment, single-segment (random nonce) | ✅ |
| 2b | Epoch keys, derived nonce mode, multi-segment | ✅ |
| 3 | Snapshot authenticator, rewrite/verify | ✅ |
| 4 | AES-256-GCM-SIV (MRAE); AEGIS/TurboSHAKE deferred | ✅ |
| 5 | Public engine API, DocC, property tests, 0.0.1 | ✅ |
| SEAL A–B | Two-product split; SEAL configuration + writer/reader lifecycle | ✅ |
| SEAL C | RW rewriter (RewriteSeg + snapshot rebind, E.17.1-pinned); §4.12 scheme presets | ✅ |
| SEAL D | Serialization layouts, hedged nonces | planned |

Suite coverage: **AEAD** AES-128/256-GCM, ChaCha20-Poly1305, AES-256-GCM-SIV; **KDF**
HKDF-SHA-256/384/512. AEGIS and TurboSHAKE are documented future work
([`Spec/STAGE4-FEASIBILITY.md`](Spec/STAGE4-FEASIBILITY.md)).

Every cryptographic stage is validated **byte-exact** against the draft's Appendix E
test vectors (vendored under `Tests/RAAETests/Vectors/`): E.1, E.5, E.9, E.16.1, E.17.1,
and the E.20.1 negative case.

## Contributing and Collaboration

We welcome contributions! Please follow our
[guidelines for contributing code](./CONTRIBUTING.md).

Germ has adopted the [Contributor Covenant](./CODE_OF_CONDUCT.md) code of conduct.

## License

[MIT](./LICENSE).
