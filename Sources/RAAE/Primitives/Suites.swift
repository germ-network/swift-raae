import Foundation

/// Resolves the draft's `aead_id` / `kdf_id` (Tables 7–8) to concrete backends.
///
/// Stage 1 registers the swift-crypto-backed suites. Additional suites (AEGIS,
/// TurboSHAKE, AES-256-GCM-SIV) register here in Stage 4 behind the same protocols.
public enum SuiteRegistry {
	/// Resolve an AEAD by `aead_id`, or `nil` if unsupported in this build.
	public static func aead(id: UInt16) -> AEAD? {
		switch id {
		case 0x0001: AES128GCM()
		case 0x0002: AES256GCM()
		case 0x001D: ChaCha20Poly1305()
		case 0x001F: AES256GCMSIV()
		default: nil
		}
	}

	/// Resolve a KDF by `kdf_id`, or `nil` if unsupported in this build.
	public static func kdf(id: UInt16) -> KeyDerivation? {
		switch id {
		case 0x0001: makeHKDFSHA256()
		case 0x0002: makeHKDFSHA384()
		case 0x0003: makeHKDFSHA512()
		default: nil
		}
	}

	/// Whether a `snap_id` is a supported code point. There is no snapshot backend
	/// type to resolve — ``MaskedMultisetHash`` is the only authenticator — so unlike
	/// ``aead(id:)``/``kdf(id:)`` this is a validity predicate rather than a factory.
	/// draft-02 additionally defines `snap_id` 0x0002 (digest transcript) and 0x0003
	/// (epoch digest tree); this build implements neither, so both are unknown here and
	/// `PayloadSchedule.init` rejects them as `unsupportedSnapID`.
	public static func isKnownSnapID(_ id: UInt16) -> Bool {
		id == SnapID.none || id == SnapID.maskedMultisetHash
	}
}

/// `snap_id` code points (draft-02 Table 12). Only the two implemented here are named;
/// draft-02 also defines 0x0002 (digest transcript) and 0x0003 (epoch digest tree),
/// which are unimplemented and rejected by ``SuiteRegistry/isKnownSnapID(_:)``.
public enum SnapID {
	/// No snapshot authenticator.
	public static let none: UInt16 = 0x0000
	/// Masked multiset hash (§4.7.4).
	public static let maskedMultisetHash: UInt16 = 0x0001
}

/// Profile protocol identifiers (draft §4.10.2).
public enum ProtocolID {
	/// Immutable profile.
	public static let immutable = Bytes.ascii("SEAL-RO-v1")
	/// Mutable (rewritable) profile.
	public static let mutable = Bytes.ascii("SEAL-RW-v1")
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
