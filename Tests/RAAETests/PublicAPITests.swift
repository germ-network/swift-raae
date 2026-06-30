// NOTE: plain (non-@testable) import — this exercises only the public surface, so it
// fails to compile if the engine isn't actually usable by an external consumer.
import RAAE
import Testing

@Suite("Public engine API (end-to-end)")
struct PublicAPITests {
	/// Build a schedule, encrypt segments in random mode, decrypt them back, and
	/// authenticate the set with a snapshot — using only public API.
	func makeSchedule(nonceMode: PayloadInfo.NonceMode) throws -> PayloadSchedule {
		let info = PayloadInfo(
			aeadID: 0x0002,  // AES-256-GCM
			segmentMax: 16384,
			kdfID: 0x0001,  // HKDF-SHA-256
			snapID: 0x0001,
			nonceMode: nonceMode,
			epochLength: 1,
			salt: [UInt8](repeating: 0x04, count: 32))
		return try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xAA, count: 32),
			payloadInfo: info)
	}

	@Test func randomModeRoundTripWithSnapshot() throws {
		let schedule = try makeSchedule(nonceMode: .random)
		let hash = MaskedMultisetHash(schedule: schedule)

		let messages: [[UInt8]] = [
			Array("the quick brown fox".utf8),
			Array("jumps over the lazy dog".utf8),
			Array("third and final segment".utf8),
		]

		// Encrypt each segment with a fresh nonce; collect (nonce, ct) and the tag.
		var stored: [(nonce: [UInt8], ct: [UInt8])] = []
		var tagSet: [(index: UInt64, tag: [UInt8])] = []
		for (i, message) in messages.enumerated() {
			let pos = SegmentPosition(
				index: UInt64(i), isFinal: i == messages.count - 1)
			let nonce = Segment.freshNonce(for: schedule.aead)
			let (_, ct) = try Segment.encryptRandom(
				schedule: schedule, position: pos, associatedData: [],
				plaintext: message, nonce: nonce)
			stored.append((nonce, ct))
			tagSet.append((UInt64(i), Array(ct.suffix(schedule.aead.tagLength))))
		}

		let snapshot = hash.snapshotValue(
			segmentCount: UInt64(messages.count),
			accumulator: hash.accumulator(segments: tagSet))
		#expect(hash.verify(snapshot: snapshot, segments: tagSet))

		// Decrypt in arbitrary order — random access.
		for i in messages.indices.reversed() {
			let pos = SegmentPosition(
				index: UInt64(i), isFinal: i == messages.count - 1)
			let pt = try Segment.decryptRandom(
				schedule: schedule, position: pos, associatedData: [],
				nonce: stored[i].nonce, ciphertext: stored[i].ct)
			#expect(pt == messages[i])
		}

		// The commitment lets a decryptor reject a wrong CEK up front.
		let wrong = try PayloadSchedule(
			protocolID: ProtocolID.mutable,
			cek: [UInt8](repeating: 0xBB, count: 32),
			payloadInfo: schedule.payloadInfo)
		#expect(!ConstantTime.equals(wrong.commitment, schedule.commitment))
	}

	@Test func derivedModeRoundTrip() throws {
		let schedule = try makeSchedule(nonceMode: .derived)
		let pos = SegmentPosition(index: 3, isFinal: false)
		let message = Array("derived-mode payload".utf8)
		let ct = try Segment.encryptDerived(
			schedule: schedule, position: pos, associatedData: [0x01],
			plaintext: message)
		let back = try Segment.decryptDerived(
			schedule: schedule, position: pos, associatedData: [0x01], ciphertext: ct)
		#expect(back == message)
	}

	@Test func unsupportedSuiteThrows() {
		let info = PayloadInfo(
			aeadID: 0x0021,  // AEGIS-256 — cut from v1
			segmentMax: 16384, kdfID: 0x0001, snapID: 0x0001,
			nonceMode: .random, epochLength: 0,
			salt: [UInt8](repeating: 0x04, count: 32))
		#expect(throws: PayloadSchedule.ScheduleError.self) {
			try PayloadSchedule(
				protocolID: ProtocolID.mutable,
				cek: [UInt8](repeating: 0xAA, count: 32),
				payloadInfo: info)
		}
	}
}
