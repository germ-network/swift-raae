import Crypto
import Foundation
import _CryptoExtras

/// AES-256-GCM-SIV, `aead_id = 0x001F` (Table 7, IANA `AEAD_AES_256_GCM_SIV`).
/// `Nk=32, Nn=12, Nt=16`.
///
/// This is the MRAE (nonce-misuse-resistant) suite SEAL uses for derived nonce mode:
/// a rewrite reuses the segment's fixed nonce, and GCM-SIV's synthetic IV bounds the
/// damage of that reuse to leaking equality of identical plaintext/context pairs.
/// Backed by swift-crypto's `_CryptoExtras` (BoringSSL).
struct AES256GCMSIV: AEAD {
	let id: UInt16 = 0x001F
	let keyLength = 32
	let nonceLength = 12
	let tagLength = 16
	let isMRAE = true

	func seal(key: [UInt8], nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8]
	{
		guard key.count == keyLength else {
			throw AEADError.invalidParameters(
				"key must be \(keyLength) octets, got \(key.count)")
		}
		guard nonce.count == nonceLength else {
			throw AEADError.invalidParameters(
				"nonce must be \(nonceLength) octets, got \(nonce.count)")
		}
		let box = try AES.GCM._SIV.seal(
			plaintext,
			using: SymmetricKey(data: key),
			nonce: try AES.GCM._SIV.Nonce(data: nonce),
			authenticating: aad
		)
		return Array(box.ciphertext) + Array(box.tag)
	}

	func open(key: [UInt8], nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8]
	{
		guard key.count == keyLength else {
			throw AEADError.invalidParameters(
				"key must be \(keyLength) octets, got \(key.count)")
		}
		guard nonce.count == nonceLength else {
			throw AEADError.invalidParameters(
				"nonce must be \(nonceLength) octets, got \(nonce.count)")
		}
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let ct = Array(ciphertext.prefix(ciphertext.count - tagLength))
		let tag = Array(ciphertext.suffix(tagLength))
		do {
			let box = try AES.GCM._SIV.SealedBox(
				nonce: try AES.GCM._SIV.Nonce(data: nonce), ciphertext: ct, tag: tag
			)
			return Array(
				try AES.GCM._SIV.open(
					box, using: SymmetricKey(data: key), authenticating: aad))
		} catch {
			throw AEADError.authenticationFailure
		}
	}
}
