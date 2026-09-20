import Crypto
import Foundation
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
			ikm: SymmetricKey(data: [1, 2, 3]), info: [], outputLength: 32)
		let b = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [], outputLength: 32)
		#expect(a == b)
		#expect(a.count == 32)
	}

	@Test func outputLengthIsHonored() {
		let kdf = makeHKDFSHA256()
		for length in [16, 32, 48, 100] {
			let out = kdf.derive(
				protocolID: ProtocolID.immutable, label: Label.payloadKey,
				ikm: SymmetricKey(data: [9]), info: [], outputLength: length)
			#expect(out.count == length)
		}
	}

	@Test func labelSeparatesOutputs() {
		let kdf = makeHKDFSHA256()
		let commit = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [], outputLength: 32)
		let payload = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.payloadKey,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [], outputLength: 32)
		#expect(commit != payload)
	}

	@Test func protocolIDSeparatesOutputs() {
		let kdf = makeHKDFSHA256()
		let ro = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.commit,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [], outputLength: 32)
		let rw = kdf.derive(
			protocolID: ProtocolID.mutable, label: Label.commit,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [], outputLength: 32)
		#expect(ro != rw)
	}

	@Test func infoSeparatesOutputs() {
		let kdf = makeHKDFSHA256()
		let a = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.nonceBase,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [[0x00]], outputLength: 32)
		let b = kdf.derive(
			protocolID: ProtocolID.immutable, label: Label.nonceBase,
			ikm: SymmetricKey(data: [1, 2, 3]), info: [[0x01]], outputLength: 32)
		#expect(a != b)
	}

	@Test func longHashReturnsNhOctets() {
		#expect(makeHKDFSHA256().longHash([1, 2, 3]).count == 32)
		#expect(makeHKDFSHA512().longHash([1, 2, 3]).count == 64)
	}

	/// An ikm beyond the framing literal limit takes §4.3's escape — `0xFFFF || LH(ikm)`
	/// — and stays extractable. No derivation in this package reaches that size, but the
	/// fallback path must not trap in `Bytes.uint16` (or emit the marker followed by raw
	/// bytes) if one ever does.
	@Test func overLargeIKMTakesTheEscape() {
		let kdf = makeHKDFSHA256()
		let large = [UInt8](repeating: 0xAB, count: Framing.maxLiteralLength + 2)
		let derived = kdf.deriveKey(
			protocolID: ProtocolID.mutable, label: Label.payloadKey,
			ikm: SymmetricKey(data: large), info: [[0x07]], outputLength: 32)

		let extractInput = Framing.encode(
			[ProtocolID.mutable, Label.payloadKey, large], longHash: kdf.longHash)
		let markerAt = 2 + ProtocolID.mutable.count + 2 + Label.payloadKey.count
		#expect(Array(extractInput[markerAt..<(markerAt + 2)]) == [0xFF, 0xFF])
		#expect(extractInput.count == markerAt + 2 + kdf.outputSize)

		let prk = HKDF<SHA256>.extract(
			inputKeyMaterial: SymmetricKey(data: extractInput), salt: ProtocolID.mutable
		)
		let expected = HKDF<SHA256>.expand(
			pseudoRandomKey: prk,
			info: Framing.encode(
				[ProtocolID.mutable, Label.payloadKey, [0x07], Bytes.uint16(32)],
				longHash: kdf.longHash),
			outputByteCount: 32)
		#expect(
			derived.withUnsafeBytes { Data($0) }
				== expected.withUnsafeBytes { Data($0) },
			"the derived key must match an independent HKDF over the framed input")
	}

	/// The largest literal ikm stays a literal `uint16(len) || ikm` — the escape starts
	/// strictly above the limit.
	@Test func largestLiteralIKMStaysLiteral() {
		let kdf = makeHKDFSHA256()
		let largest = [UInt8](repeating: 0xCD, count: Framing.maxLiteralLength)
		let derived = kdf.deriveKey(
			protocolID: ProtocolID.mutable, label: Label.commit,
			ikm: SymmetricKey(data: largest), info: [], outputLength: 32)

		let extractInput = Framing.encode(
			[ProtocolID.mutable, Label.commit, largest], longHash: kdf.longHash)
		let prefixWidth = 2 + ProtocolID.mutable.count + 2 + Label.commit.count
		#expect(
			Array(extractInput[prefixWidth..<(prefixWidth + 2)])
				== Bytes.uint16(Framing.maxLiteralLength))
		#expect(extractInput.count == prefixWidth + 2 + largest.count)

		let prk = HKDF<SHA256>.extract(
			inputKeyMaterial: SymmetricKey(data: extractInput), salt: ProtocolID.mutable
		)
		let expected = HKDF<SHA256>.expand(
			pseudoRandomKey: prk,
			info: Framing.encode(
				[ProtocolID.mutable, Label.commit, Bytes.uint16(32)],
				longHash: kdf.longHash),
			outputByteCount: 32)
		#expect(
			derived.withUnsafeBytes { Data($0) }
				== expected.withUnsafeBytes { Data($0) },
			"the derived key must match an independent HKDF over the framed input")
	}
}
