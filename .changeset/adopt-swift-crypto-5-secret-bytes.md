---
"@germ-network/swift-raae": minor
---

Adopt swift-crypto 5.0 and `swift-secret-bytes` 0.5, moving the remaining secret
material out of plain heap `[UInt8]` and into zeroizing custody. The wire format is
unchanged: every Appendix F vector still derives byte-identical keys, commitments,
segments, and snapshots.

**Three breaking API changes.**

- **The CEK is a `SymmetricKey`, not `[UInt8]`/`Data`.** Every public entry point —
  `PayloadSchedule.init(cek:)`/`startDecrypt(cek:)`, the SEAL engine's
  `startEncryption`/`resumeWriting`/`startDecryption`, and the `Data`-based container and
  envelope entry points (`seal`/`open`/`sealEnvelope`/`SEALEnvelope.open`/`startDecryption`)
  — now takes a `SymmetricKey`; `SEALConfiguration.generateCEK()` returns one. A host
  holding raw CEK bytes bridges once at its call site with `SymmetricKey(data:)`. The CEK
  never crosses the public surface as an unscrubbed array, and it flows into derivation
  with no byte conversion at all. `invalidCEKLength` is preserved via
  `cek.bitCount == 256`.

- **`KeyDerivation` narrows `ikm` from `[[UInt8]]` to a single `SymmetricKey`.** Every
  derivation in the draft mixes exactly one secret, so the list form only ever held one
  element; `info` stays a list. Implementations of the protocol must update. `Framing`
  is unchanged and still encodes each `info` element individually.

- **`Segment.derivedNonce(nonceBase:)` takes a `SecretBytes`, not `[UInt8]`.** The
  draft's §4.5.3 primitive stays public for implementers and vector tooling; a caller
  holding the nonce base as bytes wraps it once with `SecretBytes(bytes:)`. `nonce_base`
  is a *nonce*, not a key — it is never passed to a key-taking API — so it is held in
  `SecretBytes` custody rather than `SymmetricKey`, exactly as the accumulator is. The
  *returned* nonce stays `[UInt8]`: AEAD security requires nonce *uniqueness*, not secrecy,
  and the value is an immediate AEAD input. It is a masked copy of the base — low 8 octets
  XORed, the rest copied verbatim — which `Spec/NOTES.md` records as the honest limit.

**Platform floor.** The deployment floor rises to **macOS 15 / iOS 18** (was 14/17),
forced by `swift-secret-bytes` 0.5, and the package now needs a Swift 6.2 toolchain.
The CI Linux container moves to `swift:6.2`.

**Internal custody.** The HKDF framing tail (`frame(ikm)`), the snapshot accumulator
held by `SEALWriter`/`SEALRewriter` (now `SecretBytes` — optional on the writer, nil
when the profile runs no snapshot authenticator), and the `nonce_base` XOR are
built in zeroizing storage on platforms whose CryptoKit exposes swift-crypto 5.0's span
surface (macOS 27 / iOS 27 and newer), with the previous array path as the fallback
below that. The per-segment AEAD gains an internal in-place span fast path over GCM and
ChaChaPoly — the public `AEAD` protocol does not change, and `AES.GCM._SIV` (no span
surface) keeps its existing path. A package-scoped seam (`forceArrayPath`) lets the two
paths be diffed in-process; both reproduce the published vectors exactly.
