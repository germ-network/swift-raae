import Crypto
import Foundation

/// Errors raised by the AEAD layer.
public enum AEADError: Error, Equatable {
	/// Key, nonce, or ciphertext length did not match the algorithm's parameters.
	case invalidParameters(String)
	/// Authentication failed on `open` (tag mismatch / tampered input).
	case authenticationFailure
}

/// An AEAD as parameterized by the draft (Table 7). For every Table-7 AEAD the output
/// is `C_i = ct_i || tag_i` with the tag in the final `Nt` octets (§4.8).
public protocol AEAD: Sendable {
	/// `aead_id` from Table 7.
	var id: UInt16 { get }
	/// Key size in octets (`Nk` in the draft).
	var keyLength: Int { get }
	/// Nonce size in octets (`Nn` in the draft).
	var nonceLength: Int { get }
	/// Tag size in octets (`Nt` in the draft).
	var tagLength: Int { get }

	/// Whether this AEAD is nonce-misuse-resistant (MRAE). Derived nonce mode reuses a
	/// segment's fixed nonce on rewrite, so a rewritable profile must use an MRAE AEAD
	/// (draft Table 4). Defaults to `false`.
	var isMRAE: Bool { get }

	/// Encrypt, returning `ct || tag`. The key is a `SymmetricKey` so segment keys never
	/// cross this boundary as a raw `[UInt8]`.
	func seal(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws
		-> [UInt8]

	/// Decrypt `ct || tag`, returning the plaintext or throwing `authenticationFailure`.
	func open(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws
		-> [UInt8]
}

extension AEAD {
	/// Non-MRAE by default; MRAE suites (e.g. AES-256-GCM-SIV) override.
	public var isMRAE: Bool { false }

	/// Validate key/nonce sizes against the algorithm parameters.
	fileprivate func validate(key: SymmetricKey, nonce: [UInt8]) throws {
		guard key.bitCount == keyLength * 8 else {
			throw AEADError.invalidParameters(
				"key must be \(keyLength) octets, got \(key.bitCount / 8)")
		}
		guard nonce.count == nonceLength else {
			throw AEADError.invalidParameters(
				"nonce must be \(nonceLength) octets, got \(nonce.count)")
		}
	}
}

/// AES-128-GCM, `aead_id = 0x0001` (Table 7). `Nk=16, Nn=12, Nt=16`.
struct AES128GCM: AEAD {
	let id: UInt16 = 0x0001
	let keyLength = 16
	let nonceLength = 12
	let tagLength = 16

	func seal(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws
		-> [UInt8]
	{
		try validate(key: key, nonce: nonce)
		let box = try AES.GCM.seal(
			plaintext,
			using: key,
			nonce: try AES.GCM.Nonce(data: nonce),
			authenticating: aad
		)
		return Array(box.ciphertext) + Array(box.tag)
	}

	func open(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws
		-> [UInt8]
	{
		try validate(key: key, nonce: nonce)
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let ct = Array(ciphertext.prefix(ciphertext.count - tagLength))
		let tag = Array(ciphertext.suffix(tagLength))
		do {
			let box = try AES.GCM.SealedBox(
				nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
			return Array(
				try AES.GCM.open(
					box, using: key, authenticating: aad))
		} catch {
			throw AEADError.authenticationFailure
		}
	}
}

/// AES-256-GCM, `aead_id = 0x0002` (Table 7). `Nk=32, Nn=12, Nt=16`.
struct AES256GCM: AEAD {
	let id: UInt16 = 0x0002
	let keyLength = 32
	let nonceLength = 12
	let tagLength = 16

	func seal(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws
		-> [UInt8]
	{
		try validate(key: key, nonce: nonce)
		let box = try AES.GCM.seal(
			plaintext,
			using: key,
			nonce: try AES.GCM.Nonce(data: nonce),
			authenticating: aad
		)
		return Array(box.ciphertext) + Array(box.tag)
	}

	func open(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws
		-> [UInt8]
	{
		try validate(key: key, nonce: nonce)
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let ct = Array(ciphertext.prefix(ciphertext.count - tagLength))
		let tag = Array(ciphertext.suffix(tagLength))
		do {
			let box = try AES.GCM.SealedBox(
				nonce: try AES.GCM.Nonce(data: nonce),
				ciphertext: ct,
				tag: tag
			)
			return Array(
				try AES.GCM.open(
					box, using: key, authenticating: aad))
		} catch {
			throw AEADError.authenticationFailure
		}
	}
}

/// ChaCha20-Poly1305, `aead_id = 0x001D` (Table 7, IANA `AEAD_CHACHA20_POLY1305`).
/// `Nk=32, Nn=12, Nt=16`.
struct ChaCha20Poly1305: AEAD {
	let id: UInt16 = 0x001D
	let keyLength = 32
	let nonceLength = 12
	let tagLength = 16

	func seal(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws
		-> [UInt8]
	{
		try validate(key: key, nonce: nonce)
		let box = try ChaChaPoly.seal(
			plaintext,
			using: key,
			nonce: try ChaChaPoly.Nonce(data: nonce),
			authenticating: aad
		)
		return Array(box.ciphertext) + Array(box.tag)
	}

	func open(key: SymmetricKey, nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws
		-> [UInt8]
	{
		try validate(key: key, nonce: nonce)
		guard ciphertext.count >= tagLength else {
			throw AEADError.invalidParameters(
				"ciphertext shorter than tag (\(tagLength) octets)")
		}
		let ct = Array(ciphertext.prefix(ciphertext.count - tagLength))
		let tag = Array(ciphertext.suffix(tagLength))
		do {
			let box = try ChaChaPoly.SealedBox(
				nonce: try ChaChaPoly.Nonce(data: nonce),
				ciphertext: ct,
				tag: tag
			)
			return Array(
				try ChaChaPoly.open(
					box, using: key, authenticating: aad))
		} catch {
			throw AEADError.authenticationFailure
		}
	}
}
