import RAAE
import SEAL
import Testing

@Suite("SEAL profiles and engine caps")
struct SEALProfileTests {
	@Test func protocolIDsMatchSpec() {
		// §4.10.2 wire identifiers, pinned both against the core constants and the
		// literal ASCII bytes so neither side can drift silently.
		#expect(SEALProfile.readOnly.protocolID == ProtocolID.immutable)
		#expect(SEALProfile.readWrite.protocolID == ProtocolID.mutable)
		#expect(SEALProfile.readOnly.protocolID == Array("SEAL-RO-v1".utf8))
		#expect(SEALProfile.readWrite.protocolID == Array("SEAL-RW-v1".utf8))
	}

	@Test func engineCapIsStricterThanSpecBound() {
		#expect(SEALLimits.maxSegments == UInt64(1) << 48)
		// The engine cap must sit inside the spec's derived-mode bound (§4.5.3.2),
		// so everything the engine accepts is spec-valid.
		#expect(SEALLimits.maxSegments < UInt64(1) << 63)
	}
}
