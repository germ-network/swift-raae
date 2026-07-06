import RAAE
import Testing

/// Derived-nonce index range (§4.5.3): `(i<<1)|is_final` must fit the 64-bit value
/// XORed into `nonce_base`. Swift's `<<` silently discards the shifted-out top bit, so
/// an index ≥ 2^63 would alias the nonce of `index − 2^63`; the engine rejects it with
/// a typed error instead of silently truncating.
@Suite("Derived-nonce index range")
struct DerivedNonceRangeTests {
	static let maxIndex = (UInt64(1) << 63) - 1

	@Test func boundaryIndexIsAccepted() throws {
		let base = [UInt8](repeating: 0, count: 12)
		// The largest legal index derives a nonce whose low 8 octets encode
		// (i<<1)|is_final exactly: 2^64 − 2 for is_final = 0, 2^64 − 1 for 1.
		let atMax = try Segment.derivedNonce(
			nonceBase: base, position: .init(index: Self.maxIndex, isFinal: false))
		#expect(Hex.encode(atMax) == "00000000" + "fffffffffffffffe")
		let atMaxFinal = try Segment.derivedNonce(
			nonceBase: base, position: .init(index: Self.maxIndex, isFinal: true))
		#expect(Hex.encode(atMaxFinal) == "00000000" + "ffffffffffffffff")
	}

	@Test func overflowingIndexIsRejected() {
		let base = [UInt8](repeating: 0, count: 12)
		for index in [UInt64(1) << 63, UInt64.max] {
			#expect(throws: Segment.SegmentError.indexTooLargeForDerivedMode(index)) {
				_ = try Segment.derivedNonce(
					nonceBase: base,
					position: .init(index: index, isFinal: false))
			}
		}
	}

	@Test func encryptAndDecryptInheritTheGuard() throws {
		let info = PayloadInfo(
			aeadID: 0x001F, segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: .derived, epochLength: 0,
			salt: [UInt8](repeating: 0x04, count: 32))
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32), payloadInfo: info)
		let bad = SegmentPosition(index: UInt64(1) << 63, isFinal: false)
		#expect(
			throws: Segment.SegmentError.indexTooLargeForDerivedMode(bad.index)
		) {
			_ = try Segment.encryptDerived(
				schedule: schedule, position: bad, associatedData: [],
				plaintext: [1, 2, 3])
		}
		#expect(
			throws: Segment.SegmentError.indexTooLargeForDerivedMode(bad.index)
		) {
			_ = try Segment.decryptDerived(
				schedule: schedule, position: bad, associatedData: [],
				ciphertext: [UInt8](repeating: 0, count: 19))
		}
	}
}
