import Testing

@testable import RAAE

@Suite("KDF (§4.3)")
struct KDFTests {
	@Test func hkdfParameters() {
		#expect(makeHKDFSHA256().outputSize == 32)
		#expect(makeHKDFSHA256().id == 0x0001)
		#expect(makeHKDFSHA384().outputSize == 48)
		#expect(makeHKDFSHA384().id == 0x0002)
		#expect(makeHKDFSHA512().outputSize == 64)
		#expect(makeHKDFSHA512().id == 0x0003)
	}

	@Test func deriveIsDeterministic() {
		let kdf = makeHKDFSHA256()
		let a = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: [[1, 2, 3]], info: [], outputLength: 32)
		let b = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: [[1, 2, 3]], info: [], outputLength: 32)
		#expect(a == b)
		#expect(a.count == 32)
	}

	@Test func outputLengthIsHonored() {
		let kdf = makeHKDFSHA256()
		for length in [16, 32, 48, 100] {
			let out = kdf.derive(
				protocolID: ProtocolID.immutable, label: Label.payloadKey,
				ikm: [[9]], info: [], outputLength: length)
			#expect(out.count == length)
		}
	}

	@Test func labelSeparatesOutputs() {
		let kdf = makeHKDFSHA256()
		let commit = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: [[1, 2, 3]], info: [], outputLength: 32)
		let payload = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.payloadKey,
			ikm: [[1, 2, 3]], info: [], outputLength: 32)
		#expect(commit != payload)
	}

	@Test func protocolIDSeparatesOutputs() {
		let kdf = makeHKDFSHA256()
		let ro = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: [[1, 2, 3]], info: [], outputLength: 32)
		let rw = kdf.derive(
			protocolID: ProtocolID.mutable, label: Label.commit,
			ikm: [[1, 2, 3]], info: [], outputLength: 32)
		#expect(ro != rw)
	}

	@Test func infoSeparatesOutputs() {
		let kdf = makeHKDFSHA256()
		let a = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.nonceBase,
			ikm: [[1, 2, 3]], info: [[0x00]], outputLength: 32)
		let b = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.nonceBase,
			ikm: [[1, 2, 3]], info: [[0x01]], outputLength: 32)
		#expect(a != b)
	}

	@Test func longHashReturnsNhOctets() {
		#expect(makeHKDFSHA256().longHash([1, 2, 3]).count == 32)
		#expect(makeHKDFSHA512().longHash([1, 2, 3]).count == 64)
	}
}
