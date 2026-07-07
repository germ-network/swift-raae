import Foundation

/// Per-key encryption budget derived from the suite + geometry (draft §5.9).
///
/// All limits are expressed as **base-2 logarithms** so the astronomically large bounds
/// (e.g. `2^48`) never need to be formed as an `Int`. `§5.9.5` makes tracking a normative
/// MUST: applications must freeze an object before a budget is exceeded — the CEK cannot
/// be rotated in place, so continued writing needs a new object under a fresh CEK.
/// The SEAL engine's writer meters these bounds with hard caps; a host driving the core
/// directly owns the accounting.
public struct UsageBudget: Equatable, Sendable {
	/// `log2` of allowed segment encryptions per **epoch key** — the random-nonce
	/// collision pool (§5.9.7.1) in random mode, the MRAE distinct-derived-nonce pool
	/// (§5.9.7.4) in derived mode, or the structural cap `r` (2^r segment indices per
	/// epoch key) in write-once derived mode with a non-MRAE AEAD (§4.5.3.2).
	public let perEpochKeyLog2: Int
	/// `log2` of allowed encryptions of one **segment** at its fixed derived nonce (the
	/// MRAE hot-rewrite cap, §5.9.7.4); `0` in write-once derived mode with a non-MRAE
	/// AEAD (exactly one encryption per segment — rewriting is what the write-once
	/// profile forbids); `nil` in random mode (no separate per-segment cap).
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
			guard aead.isMRAE else {
				// §4.5.3.2: a non-MRAE AEAD in derived mode is only constructible under
				// the write-once profile, so the budget *is* the discipline: exactly one
				// encryption per segment (`perSegmentLog2 = 0`), and at most the 2^r
				// segment indices an epoch key covers (`perEpochKeyLog2 = r`). Nonces
				// are distinct by construction, so no birthday term applies.
				return UsageBudget(
					perEpochKeyLog2: Int(payloadInfo.epochLength),
					perSegmentLog2: 0,
					maxEpochKeysLog2: maxEpochKeys)
			}
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
