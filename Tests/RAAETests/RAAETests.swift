import Testing

@testable import RAAE

@Suite("Suite registry (Tables 7–8)")
struct SuiteRegistryTests {
	@Test func resolvesKnownAEADs() {
		// IANA AEAD code points (Table 7).
		#expect(SuiteRegistry.aead(id: 0x0001)?.keyLength == 16)  // AES-128-GCM
		#expect(SuiteRegistry.aead(id: 0x0002)?.keyLength == 32)  // AES-256-GCM
		#expect(SuiteRegistry.aead(id: 0x001D)?.id == 0x001D)  // ChaCha20-Poly1305
	}

	@Test func resolvesKnownKDFs() {
		#expect(SuiteRegistry.kdf(id: 0x0001)?.outputSize == 32)  // HKDF-SHA-256
		#expect(SuiteRegistry.kdf(id: 0x0002)?.outputSize == 48)  // HKDF-SHA-384
		#expect(SuiteRegistry.kdf(id: 0x0003)?.outputSize == 64)  // HKDF-SHA-512
	}

	@Test func unknownIDsAreNil() {
		// AES-256-GCM-SIV (0x001F) / AEGIS-256 (0x0021) / TurboSHAKE-256 (0x0013)
		// are not registered until Stage 4.
		#expect(SuiteRegistry.aead(id: 0x001F) == nil)
		#expect(SuiteRegistry.aead(id: 0x0021) == nil)
		#expect(SuiteRegistry.kdf(id: 0x0013) == nil)
	}
}
