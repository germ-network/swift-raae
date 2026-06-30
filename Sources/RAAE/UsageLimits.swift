import Foundation

/// Per-key encryption budget derived from the suite + geometry (draft §5.9).
///
/// All limits are expressed as **base-2 logarithms** so the astronomically large bounds
/// (e.g. `2^48`) never need to be formed as an `Int`. `§5.9.5` makes tracking a normative
/// MUST: applications must freeze an object before a budget is exceeded — the CEK cannot
/// be rotated in place, so continued writing needs a new object under a fresh CEK.
public struct UsageBudget: Equatable, Sendable {
	/// `log2` of allowed segment encryptions per **epoch key** — the random-nonce
	/// collision pool (§5.9.7.1) in random mode, or the MRAE distinct-derived-nonce pool
	/// (§5.9.7.4) in derived mode.
	public let perEpochKeyLog2: Int
	/// `log2` of allowed encryptions of one **segment** at its fixed derived nonce (the
	/// MRAE hot-rewrite cap, §5.9.7.4); `nil` in random mode (no separate per-segment cap).
	public let perSegmentLog2: Int?
	/// Distinct epoch keys per `payload_key` should stay below `2^this` (128-bit-key
	/// epoch-key-collision floor, §5.9.6); `nil` for ≥ 256-bit keys. Advisory ceiling on
	/// object size, not a per-encryption budget.
	public let maxEpochKeysLog2: Int?
}

extension PayloadSchedule {
	/// The §5.9 usage budget for this message's suite + geometry, at a target collision
	/// advantage of `2^-advantageLog2` (default `2^-32`, matching the draft's tables).
	public func usageBudget(advantageLog2: Int = 32) -> UsageBudget {
		let nn = aead.nonceLength
		let is128BitKey = aead.keyLength == 16
		let maxEpochKeys = is128BitKey ? 48 : nil

		switch payloadInfo.nonceMode {
		case .random:
			// §5.9.7.1: P(coll) ≤ q^2 / 2^(8·Nn+1) ⇒ q_max = 2^((8·Nn+1−A)/2).
			let perEpoch = max(0, (8 * nn + 1 - advantageLog2) / 2)
			return UsageBudget(
				perEpochKeyLog2: perEpoch, perSegmentLog2: nil,
				maxEpochKeysLog2: maxEpochKeys)
		case .derived:
			// §5.9.7.4: 128-bit synthetic-IV birthday over distinct nonces per epoch key,
			// and a hot-segment data-volume cap reduced by the per-segment block count L.
			let birthdayLog2 = max(0, (128 - advantageLog2) / 2)
			// segmentMax is a validated power of two ≥ 4096, so blocks/segment = segmentMax/16
			// and log2(blocks/segment) = log2(segmentMax) − 4 = trailingZeroBitCount − 4. This
			// avoids an Int(UInt32) conversion (which could trap on a 32-bit target).
			let log2L = payloadInfo.segmentMax.trailingZeroBitCount - 4
			return UsageBudget(
				perEpochKeyLog2: birthdayLog2,
				perSegmentLog2: max(0, birthdayLog2 - log2L),
				maxEpochKeysLog2: maxEpochKeys)
		}
	}
}

/// How a `PayloadEncryptor` reacts when a budget is reached (§5.9.5).
public enum BudgetPolicy: Sendable {
	/// Invoke `onBudgetEvent` but still perform the encryption.
	case warn
	/// Invoke `onBudgetEvent` and throw, refusing the encryption.
	case enforce
}

/// Emitted (under both policies) when an encryption *exceeds* a budget (the count strictly
/// passes `2^limitLog2`; the boundary encryption at exactly the limit is permitted).
public struct BudgetEvent: Sendable, Equatable {
	public enum Kind: Sendable, Equatable { case epochKey, segment }
	public let kind: Kind
	/// The epoch index (`kind == .epochKey`) or segment index (`kind == .segment`).
	public let index: UInt64
	public let count: UInt64
	public let limitLog2: Int
}

/// Thrown by `PayloadEncryptor` only under `BudgetPolicy.enforce`.
public enum BudgetError: Error, Equatable {
	case epochKeyBudgetExceeded(epochIndex: UInt64, count: UInt64, limitLog2: Int)
	case segmentRewriteBudgetExceeded(index: UInt64, count: UInt64, limitLog2: Int)
}

/// Opt-in stateful encryptor that meters per-epoch-key (and, in derived mode, per-segment)
/// encryptions against the §5.9 budget, delegating the actual crypto to the byte-exact
/// `Segment` statics. This is how the §5.9.5 MUST is satisfied for a single live writer.
///
/// - Important: accounting is in-memory and per-instance. A persisted/resumed object must
///   round-trip the full counter state through ``persistableState`` → ``seed(epochCounts:segmentRewrites:)``;
///   durability across processes is the host's responsibility (§5.9.5). Decryption is
///   intentionally not metered — the forgery bound (§5.9.7.3) is a decrypt-side property an
///   online reader cannot self-limit. The ``UsageBudget/maxEpochKeysLog2`` ceiling (§5.9.6)
///   is **advisory and not enforced** here. This class is a mutable reference type and is
///   **not** `Sendable`; serialize external access.
///
/// - Note: in derived mode the per-segment counter (``segmentRewriteCounts``) grows to one
///   entry per distinct written segment index — `O(number of segments)` memory for a
///   long-lived writer.
public final class PayloadEncryptor {
	public let schedule: PayloadSchedule
	public let budget: UsageBudget
	public var policy: BudgetPolicy
	/// Called whenever an encryption *exceeds* a budget, under both policies.
	public var onBudgetEvent: ((BudgetEvent) -> Void)?

	private var epochCounts: [UInt64: UInt64] = [:]
	private var segmentRewrites: [UInt64: UInt64] = [:]

	public init(
		schedule: PayloadSchedule, policy: BudgetPolicy = .enforce, advantageLog2: Int = 32
	) {
		self.schedule = schedule
		self.budget = schedule.usageBudget(advantageLog2: advantageLog2)
		self.policy = policy
	}

	/// Random-mode segment encryption with accounting. Pass a fresh nonce
	/// (``Segment/freshNonce(for:)``).
	public func encryptRandom(
		position: SegmentPosition, associatedData: [UInt8], plaintext: [UInt8],
		nonce: [UInt8]
	) throws -> (nonce: [UInt8], ciphertext: [UInt8]) {
		try charge(position: position)
		return try Segment.encryptRandom(
			schedule: schedule, position: position, associatedData: associatedData,
			plaintext: plaintext, nonce: nonce)
	}

	/// Derived-mode segment encryption with accounting.
	public func encryptDerived(
		position: SegmentPosition, associatedData: [UInt8], plaintext: [UInt8]
	) throws -> [UInt8] {
		try charge(position: position)
		return try Segment.encryptDerived(
			schedule: schedule, position: position, associatedData: associatedData,
			plaintext: plaintext)
	}

	/// Current encryption count for an epoch key (for inspection).
	public func count(epochIndex: UInt64) -> UInt64 { epochCounts[epochIndex] ?? 0 }

	/// The complete counter state, for persisting across a freeze (§5.9.5). Round-trips
	/// through ``seed(epochCounts:segmentRewrites:)`` — restoring **both** maps is required,
	/// or the per-segment rewrite cap silently resets on resume.
	public var persistableState:
		(epochCounts: [UInt64: UInt64], segmentRewrites: [UInt64: UInt64])
	{
		(epochCounts, segmentRewrites)
	}

	/// Snapshot of the per-segment rewrite counts (derived mode). Pairs with `seed(...)`.
	public var segmentRewriteCounts: [UInt64: UInt64] { segmentRewrites }

	/// Seed counts for a resumed object so accounting continues across a freeze (§5.9.5).
	/// Pass the full ``persistableState`` — both maps — to preserve the per-segment cap.
	public func seed(epochCounts: [UInt64: UInt64], segmentRewrites: [UInt64: UInt64] = [:]) {
		self.epochCounts = epochCounts
		self.segmentRewrites = segmentRewrites
	}

	/// Account for one segment encryption (initial write or rewrite both count, §5.9.1),
	/// committing the counters only after every applicable budget check passes.
	private func charge(position: SegmentPosition) throws {
		let epoch = position.index >> schedule.payloadInfo.epochLength
		let nextEpochCount = (epochCounts[epoch] ?? 0) + 1
		if exceeds(nextEpochCount, budget.perEpochKeyLog2) {
			onBudgetEvent?(
				BudgetEvent(
					kind: .epochKey, index: epoch, count: nextEpochCount,
					limitLog2: budget.perEpochKeyLog2))
			if policy == .enforce {
				throw BudgetError.epochKeyBudgetExceeded(
					epochIndex: epoch, count: nextEpochCount,
					limitLog2: budget.perEpochKeyLog2)
			}
		}

		var nextSegmentCount: UInt64?
		if let perSegment = budget.perSegmentLog2 {
			let count = (segmentRewrites[position.index] ?? 0) + 1
			if exceeds(count, perSegment) {
				onBudgetEvent?(
					BudgetEvent(
						kind: .segment, index: position.index, count: count,
						limitLog2: perSegment))
				if policy == .enforce {
					throw BudgetError.segmentRewriteBudgetExceeded(
						index: position.index, count: count,
						limitLog2: perSegment)
				}
			}
			nextSegmentCount = count
		}

		epochCounts[epoch] = nextEpochCount
		if let nextSegmentCount { segmentRewrites[position.index] = nextSegmentCount }
	}

	/// `count > 2^limitLog2`, guarding the `Int → shift` edges (≥ 64 ⇒ unbounded).
	private func exceeds(_ count: UInt64, _ limitLog2: Int) -> Bool {
		if limitLog2 >= 64 { return false }
		if limitLog2 < 0 { return true }
		return count > (UInt64(1) << UInt64(limitLog2))
	}
}
