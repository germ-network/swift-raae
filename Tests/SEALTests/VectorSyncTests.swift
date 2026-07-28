import Foundation
import Testing

/// The engine tests carry copies of two core-vendored Appendix F vectors (SwiftPM
/// resources cannot be shared across test targets). A draft resync must update both
/// copies; this guard fails the build the moment they drift.
@Suite("Vector copy sync")
struct VectorSyncTests {
	@Test func copiesMatchCoreVendoredOriginals() throws {
		// Locate the repo checkout from this source file's path. Test runs always
		// execute from a checkout (locally and in CI), so the sources are present.
		let sealTestsDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
		let repoRoot =
			sealTestsDir
			.deletingLastPathComponent()  // Tests/
			.deletingLastPathComponent()  // repo root
		for name in ["F16", "F17"] {
			let original = try Data(
				contentsOf: repoRoot.appendingPathComponent(
					"Tests/RAAETests/Vectors/\(name).json"))
			let copy = try Data(
				contentsOf: sealTestsDir.appendingPathComponent(
					"Vectors/\(name).json"))
			#expect(original == copy, "\(name).json drifted between test targets")
		}
	}
}
