import Testing

@testable import RAAE

/// Global associated data `G` (§4.2.4 / §4.5.1): bound into the commitment as an
/// extra framed element after `payload_info`, and into nothing else. Non-empty `G`
/// is pinned byte-exact against draft-01 Appendix E.2; the empty default reproduces
/// the vendored pre-G corpus (this package's convention — see `Spec/NOTES.md`).
@Suite("Global associated data (G)")
struct GlobalAADTests {
	/// draft-01 Appendix E.2, "G = raae-demo-g": the E.1 schedule (same CEK, salt,
	/// payload_info) with a nonempty G. Identical under both empty-G conventions,
	/// so it pins our commitment derivation against the published draft directly.
	static let demoG = Bytes.ascii("raae-demo-g")
	static let e2CommitmentHex =
		"d8eedb1fa0f77428cc33d252eb307796ae3bb911c2f6ea7a9e5b0bde312afd73"

	func e1Inputs() throws -> (cek: [UInt8], info: PayloadInfo, commitment: [UInt8]) {
		let v = try Vectors.load("E1")
		return (
			Hex.decode(v["cek_hex"] as! String),
			Vectors.payloadInfo(from: v),
			Hex.decode((v["schedule"] as! [String: Any])["commitment_hex"] as! String)
		)
	}

	@Test func emptyGMatchesVendoredE1Commitment() throws {
		// The default (empty) G omits the element, reproducing the vendored pre-G
		// corpus byte for byte — both spelled and defaulted.
		let (cek, info, commitment) = try e1Inputs()
		let defaulted = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
		let spelled = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info, globalAAD: [])
		#expect(defaulted.commitment == commitment)
		#expect(spelled.commitment == commitment)
		#expect(spelled.globalAAD.isEmpty)
	}

	@Test func nonEmptyGPinsDraftE2Vector() throws {
		// Byte-exact against draft-sullivan-cfrg-raae-01 Appendix E.2.
		let (cek, info, _) = try e1Inputs()
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			globalAAD: Self.demoG)
		#expect(Hex.encode(schedule.commitment) == Self.e2CommitmentHex)
	}

	@Test func gBindsOnlyTheCommitment() throws {
		// §4.5.1: payload_key, acc_key, and nonce_base never take G — a derived-mode
		// schedule differs from its G-less twin in the commitment alone.
		let info = PayloadInfo(
			aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: .derived, epochLength: 0,
			salt: [UInt8](repeating: 0x04, count: 32))
		let cek = [UInt8](repeating: 0xAA, count: 32)
		let bare = try PayloadSchedule(
			protocolID: ProtocolID.immutable, cek: cek, payloadInfo: info)
		let bound = try PayloadSchedule(
			protocolID: ProtocolID.immutable, cek: cek, payloadInfo: info,
			globalAAD: Self.demoG)
		#expect(bare.commitment != bound.commitment)
		#expect(keyHex(bare.payloadKey) == keyHex(bound.payloadKey))
		#expect(keyHex(bare.snapKey) == keyHex(bound.snapKey))
		#expect(keyHex(bare.nonceBase!) == keyHex(bound.nonceBase!))
		#expect(keyHex(bare.segmentKey(index: 3)) == keyHex(bound.segmentKey(index: 3)))
	}

	@Test func startDecryptBindsG() throws {
		let (cek, info, _) = try e1Inputs()
		let published = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			globalAAD: Self.demoG
		).commitment

		// The matching G re-derives and verifies.
		let schedule = try PayloadSchedule.startDecrypt(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			globalAAD: Self.demoG, publishedCommitment: published)
		#expect(schedule.commitment == published)

		// A wrong or missing G fails exactly like a wrong CEK (§4.6).
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				globalAAD: Bytes.ascii("raae-demo-h"),
				publishedCommitment: published)
		}
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: published)
		}
	}

	@Test func overLargeGFramesThroughLongHash() throws {
		// G beyond the 65534-octet literal-framing limit takes the LH escape path
		// (§4.3); distinct over-large values must still commit distinctly, and the
		// derivation must stay deterministic.
		let (cek, info, _) = try e1Inputs()
		var big = [UInt8](repeating: 0x5A, count: 70_000)
		let first = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info, globalAAD: big)
		let again = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info, globalAAD: big)
		#expect(first.commitment == again.commitment)
		big[69_999] ^= 0x01
		let tweaked = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info, globalAAD: big)
		#expect(tweaked.commitment != first.commitment)
	}
}
