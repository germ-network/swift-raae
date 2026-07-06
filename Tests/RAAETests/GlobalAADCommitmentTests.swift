import Testing

@testable import RAAE

/// §4.6 global associated data `G`, pinned to Appendix E.2 of the vendored snapshot:
/// the commitment — and only the commitment — binds `G` as one framed element after
/// `payload_info`. The empty default is itself committed (an empty final element), so
/// the E.2 default case equals the E.1 commitment.
@Suite("Global associated data commitment (E.2)")
struct GlobalAADCommitmentTests {
	let info = PayloadInfo(
		aeadID: 0x0002, segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
		nonceMode: .random, epochLength: 1,
		salt: [UInt8](repeating: 0x04, count: 32))
	let cek = [UInt8](repeating: 0xAA, count: 32)

	/// E.2 "G default (empty)": equals the E.1 commitment.
	@Test func emptyGEqualsE1Commitment() throws {
		let dflt = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
		#expect(
			Hex.encode(dflt.commitment)
				== "47ea0ec7409b9b95d676019917a19f1c5831eb236aba459063458e525d130d0c"
		)
		let explicit = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			globalAssociatedData: [])
		#expect(explicit.commitment == dflt.commitment)
	}

	/// E.2 `G = "raae-demo-g"` (11 octets, hex 726161652d64656d6f2d67).
	@Test func nonEmptyGMatchesE2() throws {
		let g = Array("raae-demo-g".utf8)
		#expect(Hex.encode(g) == "726161652d64656d6f2d67")
		let schedule = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			globalAssociatedData: g)
		#expect(
			Hex.encode(schedule.commitment)
				== "d8eedb1fa0f77428cc33d252eb307796ae3bb911c2f6ea7a9e5b0bde312afd73"
		)
		// G binds only the commitment: every other schedule key is unchanged.
		let noG = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info)
		#expect(keyHex(schedule.payloadKey) == keyHex(noG.payloadKey))
		#expect(keyHex(schedule.snapKey) == keyHex(noG.snapKey))
	}

	/// §4.6: "a wrong G fails the commitment check the same way a wrong CEK does."
	@Test func wrongGFailsStartDecrypt() throws {
		let g = Array("raae-demo-g".utf8)
		let authored = try PayloadSchedule(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			globalAssociatedData: g)
		// The right G verifies.
		_ = try PayloadSchedule.startDecrypt(
			protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
			publishedCommitment: authored.commitment, globalAssociatedData: g)
		// A wrong G — including omitting it — is an authentication failure.
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: authored.commitment,
				globalAssociatedData: Array("raae-demo-h".utf8))
		}
		#expect(throws: PayloadSchedule.CommitmentError.commitmentMismatch) {
			_ = try PayloadSchedule.startDecrypt(
				protocolID: ProtocolID.mutable, cek: cek, payloadInfo: info,
				publishedCommitment: authored.commitment)
		}
	}
}
