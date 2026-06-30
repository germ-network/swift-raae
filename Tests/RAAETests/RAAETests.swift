import Testing

@testable import RAAE

@Suite("Suite registry (Tables 7–8)")
struct SuiteRegistryTests {
	@Test func resolvesKnownAEADs() {
		#expect(SuiteRegistry.aead(id: 0x0002)?.id == 0x0002)
		#expect(SuiteRegistry.aead(id: 0x0003)?.id == 0x0003)
	}

	@Test func resolvesKnownKDFs() {
		#expect(SuiteRegistry.kdf(id: 0x0001)?.outputSize == 32)
		#expect(SuiteRegistry.kdf(id: 0x0002)?.outputSize == 64)
	}

	@Test func unknownIDsAreNil() {
		// AEGIS / TurboSHAKE / AES-256-GCM-SIV are not registered until Stage 4.
		#expect(SuiteRegistry.aead(id: 0x0010) == nil)
		#expect(SuiteRegistry.kdf(id: 0x0013) == nil)
	}
}
