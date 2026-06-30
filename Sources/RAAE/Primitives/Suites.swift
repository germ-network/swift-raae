import Foundation

/// Resolves the draft's `aead_id` / `kdf_id` (Tables 7–8) to concrete backends.
///
/// Stage 1 registers the swift-crypto-backed suites. Additional suites (AEGIS,
/// TurboSHAKE, AES-256-GCM-SIV) register here in Stage 4 behind the same protocols.
enum SuiteRegistry {
	/// Resolve an AEAD by `aead_id`, or `nil` if unsupported in this build.
	static func aead(id: UInt16) -> AEAD? {
		switch id {
		case 0x0001: AES128GCM()
		case 0x0002: AES256GCM()
		case 0x001D: ChaCha20Poly1305()
		default: nil
		}
	}

	/// Resolve a KDF by `kdf_id`, or `nil` if unsupported in this build.
	static func kdf(id: UInt16) -> KeyDerivation? {
		switch id {
		case 0x0001: makeHKDFSHA256()
		case 0x0002: makeHKDFSHA384()
		case 0x0003: makeHKDFSHA512()
		default: nil
		}
	}
}

/// Profile protocol identifiers (draft §4.10.2).
enum ProtocolID {
	/// Immutable profile.
	static let immutable = Bytes.ascii("SEAL-RO-v1")
	/// Mutable (rewritable) profile.
	static let mutable = Bytes.ascii("SEAL-RW-v1")
}

/// Schedule + snapshot label strings (draft §4.4.3 Table 3, §4.7.4).
enum Label {
	/// Profile AAD label, bound as the first element of every segment AAD (§4.4.2).
	static let aadLabel = Bytes.ascii("SEAL-DATA")
	static let commit = Bytes.ascii("commit")
	static let payloadKey = Bytes.ascii("payload_key")
	static let accKey = Bytes.ascii("acc_key")
	static let nonceBase = Bytes.ascii("nonce_base")
	static let epochKey = Bytes.ascii("epoch_key")
	static let accContrib = Bytes.ascii("acc_contrib")
	static let snapshotTag = Bytes.ascii("snapshot_tag")
	static let snapshotMask = Bytes.ascii("snapshot_mask")
}
