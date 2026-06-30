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

## Building

```sh
swift build
swift test
```

## Implementation status

| Stage | Scope | Status |
|-------|-------|--------|
| 0 | Repo bootstrap, package scaffold, CI | ✅ |
| 1 | AEAD/KDF protocols, KDF framing, swift-crypto backends | ⬜ |
| 2a | Key schedule, commitment, single-segment (random nonce) | ⬜ |
| 2b | Epoch keys, derived nonce mode, multi-segment | ⬜ |
| 3 | Snapshot authenticator, rewrite/verify | ⬜ |
| 4 | Extended suites (AEGIS, TurboSHAKE, AES-256-GCM-SIV) | ⬜ |
| 5 | Hardening, ergonomics, docs, release | ⬜ |

Conformance is validated against the draft's Appendix E test vectors (vendored under
`Tests/RAAETests/Vectors/`).

## Contributing and Collaboration

We welcome contributions! Please follow our
[guidelines for contributing code](./CONTRIBUTING.md).

Germ has adopted the [Contributor Covenant](./CODE_OF_CONDUCT.md) code of conduct.

## License

[MIT](./LICENSE).
