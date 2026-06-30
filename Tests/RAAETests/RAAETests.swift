import Testing

@testable import RAAE

@Test func packageBuilds() {
	// Stage 0 smoke test: the module compiles and the placeholder is reachable.
	#expect(RAAE.targetedDraft.contains("draft-sullivan-cfrg-raae"))
}
