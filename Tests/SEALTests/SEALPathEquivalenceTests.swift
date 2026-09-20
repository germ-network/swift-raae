import Crypto
import Foundation
import Testing

@testable import RAAE
@testable import SEAL

/// The engine's span-path vs array-path equivalence: a stored object, its snapshot,
/// and a rewrite must come out byte-identical whichever path `forceArrayPath` selects.
///
/// `.serialized`: the seam is process-global.
@Suite("Array path vs span path equivalence (engine)", .serialized)
struct SEALPathEquivalenceTests {
	@Test func immutableStoredObjectAgreesAcrossPaths() throws {
		let config = try SEALConfiguration(
			profile: .readOnly, aeadID: 0x0002, kdfID: 0x0001, segmentMax: 16384)
		let cek = SymmetricKey(data: [UInt8](repeating: 0x22, count: 32))
		let salt = [UInt8](repeating: 0x09, count: 32)
		let plaintext = Data([UInt8](repeating: 0x7E, count: 40_000))  // 3 segments

		func seal() throws -> Data {
			try config.seal(
				plaintext, cek: cek, globalAssociatedData: Data(), salt: salt)
		}

		// `defer` so a throw mid-test cannot leave the process-global seam flipped and
		// silently downgrade every later test to the array path.
		defer { forceArrayPath = false }
		forceArrayPath = false
		let span = try seal()
		forceArrayPath = true
		let array = try seal()

		#expect(span == array)
		#expect(try config.open(span, cek: cek) == plaintext)
	}

	@Test func snapshotAndRewriteAgreeAcrossPaths() throws {
		let config = try SEALConfiguration(
			profile: .readWrite, aeadID: 0x001F, kdfID: 0x0001, segmentMax: 16384)
		let cek = SymmetricKey(data: [UInt8](repeating: 0x33, count: 32))
		// Pinned salt: the two runs must share one schedule, so only the paths differ.
		let salt = [UInt8](repeating: 0x0B, count: 32)

		func authorThenRewrite() throws -> (
			snapshot: [UInt8], replacement: [UInt8], rewrittenSnapshot: [UInt8]
		) {
			let writer = try SEALWriter(
				configuration: config, cek: cek, globalAssociatedData: [],
				advantageLog2: 32, salt: salt)
			var segments: [SealedSegment] = []
			for index in 0..<3 {
				segments.append(
					try writer.encrypt(
						[UInt8](repeating: UInt8(index), count: 10),
						at: SegmentPosition(
							index: UInt64(index), isFinal: index == 2)))
			}
			let object = try writer.finalize()
			let rewriter = try config.resumeWriting(
				cek: cek, header: object.header, snapshot: object.snapshot!,
				segments: segments, usageState: object.usageState)
			let (replacement, snapshot) = try rewriter.rewrite(
				[UInt8](repeating: 0xAB, count: 10), replacing: segments[1])
			return (object.snapshot!, replacement.ciphertext, snapshot)
		}

		defer { forceArrayPath = false }
		forceArrayPath = false
		let span = try authorThenRewrite()
		forceArrayPath = true
		let array = try authorThenRewrite()

		#expect(span.snapshot == array.snapshot)
		#expect(span.replacement == array.replacement)
		#expect(span.rewrittenSnapshot == array.rewrittenSnapshot)
	}
}
