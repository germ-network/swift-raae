import Testing

@testable import RAAE

/// Global associated data `G` (§4.2.4 / §4.5.1): bound into the commitment as an
/// extra framed element after `payload_info`, and into nothing else. `G` is always
/// framed, including the empty default (a zero-length element), per
/// draft-sullivan-cfrg-raae-01; the empty default is pinned against Appendix E.1 and
/// non-empty `G` against Appendix E.2 (see `Spec/NOTES.md`).
@Suite("Global associated data (G)")
struct GlobalAADTests {
	/// draft-01 Appendix E.2, "G = raae-demo-g": the E.1 schedule (same CEK, salt,
	/// payload_info) with a nonempty G — pins our commitment derivation against the
	/// published draft directly.
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
		// The empty default is framed as a zero-length element (draft-01 convention),
		// which is exactly the commitment the vendored E.1 corpus now carries — both
		// spelled and defaulted derive it.
		let (cek, info, commitment) = try e1Inputs()
		let defaulted = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
		let spelled = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info, globalAAD: [])
		#expect(defaulted.commitment == commitment)
		#expect(spelled.commitment == commitment)
		#expect(spelled.globalAAD.isEmpty)
		// Pin the vendored value directly against draft-sullivan-cfrg-raae-01 Appendix
		// E.1 so the vendored JSON and the published draft cannot silently drift apart.
		#expect(
			Hex.encode(defaulted.commitment)
				== "47ea0ec7409b9b95d676019917a19f1c5831eb236aba459063458e525d130d0c"
		)
	}

	/// Pin the remaining vendored empty-G commitments to their draft-01 literal values.
	/// E.1 is pinned above; these complete the corpus so no resynced commitment rests on
	/// JSON↔derivation self-consistency alone (in particular E.9 and E.16 are otherwise
	/// asserted by no test). Each literal was cross-verified against an independent
	/// from-scratch implementation of the §4.3 labeled KDF, which reproduces E.1's pre-G
	/// `020e115b…` and always-framed-empty-G `47ea0ec7…` exactly. E.9 shares E.1's CEK +
	/// payload_info, so it must derive the same value.
	@Test func resyncedEmptyGCommitmentsPinnedToDraft01() throws {
		let expected: [(String, String)] = [
			("E5", "9ef7166bbce42787fd834f79d29f85b66a050b24f372ecfb79a66b3f2fdc1acb"),
			("E9", "47ea0ec7409b9b95d676019917a19f1c5831eb236aba459063458e525d130d0c"),
			("E16", "9285553e10209c27bb5858b621426513b0832f26d7ee813d9dd62c218ce6972a"),
			("E17", "bf20f8c7691934f0ccf767b2a5ac19e467228674414f68d839a6698a3edd1813"),
		]
		for (name, hex) in expected {
			let v = try Vectors.load(name)
			// Derived value matches the independently-verified draft-01 literal …
			let schedule = try Vectors.schedule(from: v)
			#expect(
				Hex.encode(schedule.commitment) == hex,
				"\(name) derived commitment"
			)
			// … and the vendored JSON carries that same literal (guards the stored datum).
			let stored = (v["schedule"] as! [String: Any])["commitment_hex"] as! String
			#expect(stored == hex, "\(name) stored commitment_hex")
		}
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
