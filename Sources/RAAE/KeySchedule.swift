import Foundation

/// The payload schedule (draft §4.5.1–4.5.2): the keys derived deterministically from
/// the CEK and `payload_info`. Holds the resolved suite backends for the message.
struct PayloadSchedule {
	let protocolID: [UInt8]
	let payloadInfo: PayloadInfo
	let aead: AEAD
	let kdf: KeyDerivation

	/// Truncated KDF output binding CEK + parameters (§4.6). Length defaults to `Nh`.
	let commitment: [UInt8]
	/// Root key for per-segment (epoch) key derivation.
	let payloadKey: [UInt8]
	/// Snapshot authenticator key (`acc_key`).
	let snapKey: [UInt8]
	/// Base nonce for derived mode; `nil` in random mode.
	let nonceBase: [UInt8]?

	/// Minimum commitment length (§4.6).
	static let minCommitmentLength = 16

	enum ScheduleError: Error, Equatable {
		case unsupportedAEAD(UInt16)
		case unsupportedKDF(UInt16)
		case commitmentTooShort(Int)
	}

	/// Derive the schedule from a 32-octet CEK and the message's `payload_info`.
	///
	/// - Parameter commitmentLength: defaults to the KDF's `Nh`; must be ≥ 16.
	init(
		protocolID: [UInt8],
		cek: [UInt8],
		payloadInfo: PayloadInfo,
		commitmentLength: Int? = nil
	) throws {
		try payloadInfo.validate()
		guard let aead = SuiteRegistry.aead(id: payloadInfo.aeadID) else {
			throw ScheduleError.unsupportedAEAD(payloadInfo.aeadID)
		}
		guard let kdf = SuiteRegistry.kdf(id: payloadInfo.kdfID) else {
			throw ScheduleError.unsupportedKDF(payloadInfo.kdfID)
		}
		let commitLen = commitmentLength ?? kdf.outputSize
		guard commitLen >= Self.minCommitmentLength else {
			throw ScheduleError.commitmentTooShort(commitLen)
		}

		self.protocolID = protocolID
		self.payloadInfo = payloadInfo
		self.aead = aead
		self.kdf = kdf

		let info = payloadInfo.kdfInfoElements
		self.commitment = kdf.derive(
			protocolID: protocolID, label: Label.commit,
			ikm: [cek], info: info, outputLength: commitLen)
		self.payloadKey = kdf.derive(
			protocolID: protocolID, label: Label.payloadKey,
			ikm: [cek], info: info, outputLength: aead.keyLength)
		self.snapKey = kdf.derive(
			protocolID: protocolID, label: Label.accKey,
			ikm: [cek], info: info, outputLength: kdf.outputSize)
		self.nonceBase =
			payloadInfo.nonceMode == .derived
			? kdf.derive(
				protocolID: protocolID, label: Label.nonceBase,
				ikm: [cek], info: info, outputLength: aead.nonceLength)
			: nil
	}

	/// `segment_key(i) = KDF(protocol_id, "epoch_key", [payload_key], [uint64(i >> r)], Nk)` (§4.5.2).
	func segmentKey(index: UInt64) -> [UInt8] {
		let epochIndex = index >> payloadInfo.epochLength
		return kdf.derive(
			protocolID: protocolID, label: Label.epochKey,
			ikm: [payloadKey], info: [Bytes.uint64(epochIndex)],
			outputLength: aead.keyLength)
	}
}
