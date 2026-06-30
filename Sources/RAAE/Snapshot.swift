import Crypto
import Foundation

/// Constant-time byte comparison for authenticators (commitment, snapshot).
public enum ConstantTime {
	/// `true` iff the two byte strings are equal, in time independent of where they
	/// differ (length is treated as public).
	public static func equals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
		guard lhs.count == rhs.count else { return false }
		var diff: UInt8 = 0
		for i in lhs.indices {
			diff |= lhs[i] ^ rhs[i]
		}
		return diff == 0
	}
}

/// Masked multiset hash snapshot authenticator (`snap_id = 0x0001`, draft §4.7.4).
///
/// Publishes `snapshot = (acc XOR mask) || snapshot_tag`, where `acc` is the XOR of the
/// per-segment contributions, the tag is a MAC over `(n_seg, acc)`, and the mask is a
/// deterministic one-time pad derived from the tag. The accumulator is order-independent
/// and updates in O(1) on rewrite.
public struct MaskedMultisetHash {
	public let protocolID: [UInt8]
	public let kdf: KeyDerivation
	/// Snapshot key (`acc_key`). Internal + zeroizing; the draft (§5.8) keeps it off any
	/// public API.
	let snapKey: SymmetricKey

	/// `Nh` — the accumulator/tag/mask width.
	public var outputSize: Int { kdf.outputSize }

	public init(schedule: PayloadSchedule) {
		self.protocolID = schedule.protocolID
		self.kdf = schedule.kdf
		self.snapKey = schedule.snapKey
	}

	init(protocolID: [UInt8], kdf: KeyDerivation, snapKey: SymmetricKey) {
		self.protocolID = protocolID
		self.kdf = kdf
		self.snapKey = snapKey
	}

	/// The (secret) snap_key as a transient `[UInt8]` ikm for framing. See the note on
	/// ``KeyDerivation/deriveKey(protocolID:label:ikm:info:outputLength:)``.
	private var snapKeyBytes: [UInt8] { snapKey.withUnsafeBytes { Array($0) } }

	/// `contrib(i) = KDF(protocol_id, "acc_contrib", [snap_key], [uint64(i), tag(i)], Nh)`.
	public func contribution(index: UInt64, tag: [UInt8]) -> [UInt8] {
		kdf.derive(
			protocolID: protocolID, label: Label.accContrib,
			ikm: [snapKeyBytes], info: [Bytes.uint64(index), tag],
			outputLength: outputSize)
	}

	/// `acc = XOR of contrib(i)` over the supplied segments (order-independent).
	public func accumulator(segments: [(index: UInt64, tag: [UInt8])]) -> [UInt8] {
		var acc = [UInt8](repeating: 0, count: outputSize)
		for segment in segments {
			acc = xor(acc, contribution(index: segment.index, tag: segment.tag))
		}
		return acc
	}

	/// `snapshot_tag = KDF(protocol_id, "snapshot_tag", [snap_key], [uint64(n_seg), acc], Nh)`.
	public func snapshotTag(segmentCount: UInt64, accumulator: [UInt8]) -> [UInt8] {
		kdf.derive(
			protocolID: protocolID, label: Label.snapshotTag,
			ikm: [snapKeyBytes], info: [Bytes.uint64(segmentCount), accumulator],
			outputLength: outputSize)
	}

	/// `mask = KDF(protocol_id, "snapshot_mask", [snap_key], [uint64(n_seg), snapshot_tag], Nh)`.
	public func mask(segmentCount: UInt64, snapshotTag: [UInt8]) -> [UInt8] {
		kdf.derive(
			protocolID: protocolID, label: Label.snapshotMask,
			ikm: [snapKeyBytes], info: [Bytes.uint64(segmentCount), snapshotTag],
			outputLength: outputSize)
	}

	/// The published `snapshot = (acc XOR mask) || snapshot_tag`.
	public func snapshotValue(segmentCount: UInt64, accumulator: [UInt8]) -> [UInt8] {
		let tag = snapshotTag(segmentCount: segmentCount, accumulator: accumulator)
		let pad = mask(segmentCount: segmentCount, snapshotTag: tag)
		return xor(accumulator, pad) + tag
	}

	/// O(1) rewrite update: remove the old contribution and add the new one (§4.7.4).
	/// The segment count is unchanged.
	public func rewrittenAccumulator(
		accumulator: [UInt8], index: UInt64, oldTag: [UInt8], newTag: [UInt8]
	) -> [UInt8] {
		let delta = xor(
			contribution(index: index, tag: oldTag),
			contribution(index: index, tag: newTag))
		return xor(accumulator, delta)
	}

	/// `SnapVerify`: recompute the snapshot over the present segments and compare it,
	/// constant-time, to the published value. `n_seg` is the number of segments supplied.
	public func verify(snapshot expected: [UInt8], segments: [(index: UInt64, tag: [UInt8])])
		-> Bool
	{
		let acc = accumulator(segments: segments)
		let recomputed = snapshotValue(
			segmentCount: UInt64(segments.count), accumulator: acc)
		return ConstantTime.equals(recomputed, expected)
	}

	private func xor(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
		precondition(lhs.count == rhs.count)
		var out = lhs
		for i in out.indices { out[i] ^= rhs[i] }
		return out
	}
}
