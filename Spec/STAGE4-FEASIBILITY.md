# Stage 4 — extended-suite feasibility spike

The plan gated the exotic suites on availability of a vetted Swift backend. Findings,
with the decision taken for v1.

## AES-256-GCM-SIV (`aead_id 0x001F`) — IMPLEMENTED ✅

swift-crypto's **`_CryptoExtras`** module ships `AES.GCM._SIV` (BoringSSL-backed), with
a `seal`/`open` API mirroring `AES.GCM`, plus `Nonce(data:)` and
`SealedBox(nonce:ciphertext:tag:)`. It builds on macOS, iOS, and Linux.

Decision: **implement** (`AEAD_GCMSIV.swift`). This is the MRAE suite SEAL needs for
derived-mode rewrites, and it is a vetted implementation — no hand-rolled crypto.
Verified byte-exact against Appendix **E.15.1** (derived nonces, deterministic
re-encryption, and the same-nonce rewrite).

## AEGIS-128L / AEGIS-256 (`0x0020` / `0x0021`) — CUT from v1 ❌

Not present in swift-crypto or CryptoKit. AEGIS is built from the AES round function;
a competitive implementation needs AES-NI/ARMv8-Crypto intrinsics, which CryptoKit does
not expose. The realistic backends are:
- **libsodium** (`crypto_aead_aegis256`) via a C-interop dependency, or
- a hand-written AES-round implementation (table-based ⇒ cache-timing risk, or
  intrinsics ⇒ platform-specific unsafe code).

Both add significant surface and risk for a primitive no current consumer requires.
Decision: **cut from v1**, leave the `aead_id` unregistered (registry returns `nil`).
Revisit behind the existing `AEAD` protocol if a vetted Swift AEGIS appears or a
libsodium dependency becomes acceptable.

## TurboSHAKE-256 (`kdf_id 0x0013`) — DEFERRED ❌

Not present in swift-crypto. It is the one-step XOF KDF (Keccak-p[1600,12]); the KDF
protocol already anticipates the one-step form, but the permutation itself would be a
hand-rolled Keccak. That is feasible in pure Swift (~200 lines, and a hash has no
secret-dependent control flow), and has byte-exact vectors (E.13), but it is net-new
unvetted crypto.

Decision: **defer.** It is the strongest follow-up candidate (lowest risk of the three,
clear vectors). Tracked as future work; `kdf_id 0x0013` stays unregistered for now.

## v1 suite coverage

| kind | suites |
|------|--------|
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, **AES-256-GCM-SIV** |
| KDF  | HKDF-SHA-256, HKDF-SHA-384, HKDF-SHA-512 |

Everything in this table is backed by Apple CryptoKit / swift-crypto / `_CryptoExtras`
(all vetted). AEGIS and TurboSHAKE slot in behind the same `AEAD`/`KeyDerivation`
protocols when a vetted backend is chosen.
