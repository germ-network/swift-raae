import Crypto
import Testing

@testable import RAAE

@Suite("AEAD (§4.8, Table 7)")
struct AEADTests {
	static let suites: [(String, any AEAD)] = [
		("AES-256-GCM", AES256GCM()),
		("ChaCha20-Poly1305", ChaCha20Poly1305()),
	]

	@Test(arguments: suites)
	func roundTripAndLayout(_ named: (String, any AEAD)) throws {
		let aead = named.1
		let key = SymmetricKey(data: [UInt8](repeating: 0x07, count: aead.keyLength))
		let nonce = [UInt8](repeating: 0x09, count: aead.nonceLength)
		let aad: [UInt8] = [0xA0, 0xB1]
		let plaintext = Array("hello, segment".utf8)

		let ciphertext = try aead.seal(
			key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		// C_i = ct_i || tag_i, tag is the final Nt octets.
		#expect(ciphertext.count == plaintext.count + aead.tagLength)

		let decrypted = try aead.open(
			key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
		#expect(decrypted == plaintext)
	}

	@Test(arguments: suites)
	func tamperedTagFails(_ named: (String, any AEAD)) throws {
		let aead = named.1
		let key = SymmetricKey(data: [UInt8](repeating: 0x07, count: aead.keyLength))
		let nonce = [UInt8](repeating: 0x09, count: aead.nonceLength)
		var ciphertext = try aead.seal(
			key: key, nonce: nonce, aad: [], plaintext: [1, 2, 3])
		ciphertext[ciphertext.count - 1] ^= 0xFF
		#expect(throws: AEADError.authenticationFailure) {
			try aead.open(key: key, nonce: nonce, aad: [], ciphertext: ciphertext)
		}
	}

	@Test(arguments: suites)
	func wrongAADFails(_ named: (String, any AEAD)) throws {
		let aead = named.1
		let key = SymmetricKey(data: [UInt8](repeating: 0x07, count: aead.keyLength))
		let nonce = [UInt8](repeating: 0x09, count: aead.nonceLength)
		let ciphertext = try aead.seal(
			key: key, nonce: nonce, aad: [0x01], plaintext: [1, 2, 3])
		#expect(throws: AEADError.authenticationFailure) {
			try aead.open(key: key, nonce: nonce, aad: [0x02], ciphertext: ciphertext)
		}
	}

	@Test(arguments: suites)
	func wrongKeySizeThrows(_ named: (String, any AEAD)) {
		let aead = named.1
		let nonce = [UInt8](repeating: 0x09, count: aead.nonceLength)
		#expect(throws: AEADError.self) {
			try aead.seal(
				key: SymmetricKey(data: [0x01]), nonce: nonce, aad: [],
				plaintext: [1])
		}
	}
}
