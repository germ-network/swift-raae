import Testing

@testable import RAAE

@Suite("Framing (§4.3)")
struct FramingTests {
	/// A `longHash` that must not be invoked on the literal path.
	let unusedHash: ([UInt8]) -> [UInt8] = { _ in
		Issue.record("longHash should not run for literal-length fields")
		return []
	}

	@Test func emptyFieldIsTwoZeroOctets() {
		#expect(Framing.frame([], longHash: unusedHash) == [0x00, 0x00])
	}

	@Test func shortFieldIsBigEndianLengthThenBytes() {
		#expect(Framing.frame([1, 2, 3], longHash: unusedHash) == [0x00, 0x03, 1, 2, 3])
	}

	@Test func encodeConcatenatesFramedFieldsInOrder() {
		let out = Framing.encode([[1], [2, 3]], longHash: unusedHash)
		#expect(out == [0x00, 0x01, 1, 0x00, 0x02, 2, 3])
	}

	@Test func maxLiteralLengthStaysLiteral() {
		let field = [UInt8](repeating: 0, count: 0xFFFE)
		let framed = Framing.frame(field, longHash: { _ in [0x99] })
		#expect(Array(framed.prefix(2)) == [0xFF, 0xFE])
		#expect(framed.count == 2 + 0xFFFE)
	}

	@Test func overLargeFieldUsesEscapeAndLongHash() {
		let field = [UInt8](repeating: 0xAB, count: 0xFFFF)
		let framed = Framing.frame(field, longHash: { _ in [0xDE, 0xAD] })
		#expect(Array(framed.prefix(2)) == [0xFF, 0xFF])
		#expect(Array(framed.dropFirst(2)) == [0xDE, 0xAD])
	}
}
