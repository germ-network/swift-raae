# swift-raae

A Swift implementation of **random-access authenticated encryption (raAE)** and the
**SEAL** construction (Segmented Encryption and Authentication Layer), per the IETF
draft [`draft-sullivan-cfrg-raae`](https://grittygrease.github.io/draft-sullivan-cfrg-raae/draft-sullivan-cfrg-raae.html).

> **Status: 0.1.0, pre-1.0.** The engine is complete for both profiles — write-once and
> rewritable — and every cryptographic stage is pinned byte-exact against the draft's
> Appendix F vectors. What is *not* settled is the target: `draft-sullivan-cfrg-raae` is
> an individual Internet-Draft (Informational, not CFRG-adopted) and is expected to
> change, so **stored bytes are not yet stable across draft revisions** — -02 already
> renamed two named instantiations. See [`Spec/SOURCE.md`](Spec/SOURCE.md) for the
> pinned snapshot and the resync procedure.

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
as the cross-platform backend. AES-256-GCM-SIV — the misuse-resistant suite derived
nonce mode requires under a rewritable profile — comes from its `_CryptoExtras` module.
No suite is hand-rolled: AEGIS and TurboSHAKE have no vetted Swift backend and stay
unregistered until one exists, slotting in behind the same protocols when it does
([`Spec/STAGE4-FEASIBILITY.md`](Spec/STAGE4-FEASIBILITY.md)).

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

For write-once content there is a one-call container — the reduced immutable linear
layout (§4.11.4), which together with the `.simple` preset is the spec's
`SEAL-simple(aead_id, kdf_id)` named instantiation:

```swift
let config = try SEALConfiguration(scheme: .simple, aeadID: 0x0002, kdfID: 0x0001)
let cek = Data(SEALConfiguration.generateCEK())

let object = try config.seal(payload, cek: cek)   // salt ‖ commitment ‖ segments
let back = try config.open(object, cek: cek)      // commitment checked before any segment
```

Large objects need not be held whole. Geometry comes from the byte count alone, so a
client can fetch and open one segment at a time — and resume an interrupted download:

```swift
let geometry = try config.linearGeometry(objectByteCount: contentLength)
let index = geometry.segmentIndex(containingPlaintextOffset: 5_000)!
let bytes = try await fetch(range: geometry.byteRange(ofSegment: index)!)

let reader = try config.startDecryption(cek: cek, headerBlock: headerBytes)
let chunk = try reader.decrypt(block: bytes, at: geometry.position(ofSegment: index)!)
```

Under the immutable profile no snapshot runs, so completeness rests on the final
segment opening with `is_final = 1` — see `SEALLinearPrefix` for the progressive-read
rules.

A stored object carries no suite descriptor — `kdf_id` fixes the header width, so a
reader must know the suite before it can find the first segment. `SEALEnvelope` adds a
15-octet prefix that carries it, so a blob is self-describing and readable without a
configuration in hand:

```swift
let envelope = try config.sealEnvelope(payload, cek: cek)
let back = try SEALEnvelope.open(envelope, cek: cek)   // suite resolved from the prefix
```

The prefix is our framing, not the draft's (§4.11 leaves this layer to the consuming
protocol); drop `objectOffset` octets and the remainder is the unmodified §4.11.4
object other implementations read. It is unauthenticated but commitment-bound: every
field it declares feeds key derivation, so altering one fails the commitment before any
AEAD operation rather than downgrading anything.

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
| SEAL C | RW rewriter (RewriteSeg + snapshot rebind, F.17.1-pinned); §4.12 scheme presets | ✅ |
| SEAL D3 | Immutable linear container (§4.11.4), F.23-pinned; `SEAL-simple` claimable | ✅ |
| — | `SEALEnvelope`: self-describing suite prefix over the container, 0.1.0 | ✅ |
| SEAL D1/D2/D4–D6 | Hedged + plaintext-bound nonces, extend/truncate, digest overloads | planned |

Suite coverage: **AEAD** AES-128/256-GCM, ChaCha20-Poly1305, AES-256-GCM-SIV; **KDF**
HKDF-SHA-256/384/512. AEGIS and TurboSHAKE are documented future work
([`Spec/STAGE4-FEASIBILITY.md`](Spec/STAGE4-FEASIBILITY.md)).

Every cryptographic stage is validated **byte-exact** against the draft's Appendix F
test vectors (vendored under `Tests/RAAETests/Vectors/`): F.1, F.5, F.9, F.16.1, F.17.1,
the F.22.1 negative case, and the F.23 `SEAL-simple` end-to-end KAT.

## Contributing and Collaboration

We welcome contributions! Please follow our
[guidelines for contributing code](./CONTRIBUTING.md).

Germ has adopted the [Contributor Covenant](./CODE_OF_CONDUCT.md) code of conduct.

## License

[MIT](./LICENSE).
