// swift-tools-version:6.2
import PackageDescription

let package = Package(
	name: "swift-raae",
	// swift-secret-bytes 0.5.0 sets the floor. The span fast paths riding on
	// swift-crypto 5.0 are additionally gated `#available(macOS 27, iOS 27)`,
	// with the pre-5.0 array path as the fallback below it.
	platforms: [
		.macOS(.v15),
		.iOS(.v18),
	],
	products: [
		// The granular core: byte-exact primitives for implementers and vector tooling.
		.library(name: "RAAE", targets: ["RAAE"]),
		// The high-level engine (recommended): spec-shaped lifecycle API over the core.
		.library(name: "SEAL", targets: ["SEAL"]),
	],
	dependencies: [
		// 5.0 introduces the span-based KDF/AEAD surface (SE-0447 family) the
		// fast paths call; it is OS-gated at the call sites, so the array path
		// still carries every runtime below macOS 27 / iOS 27.
		.package(url: "https://github.com/apple/swift-crypto.git", "5.0.0"..<"6.0.0"),
		// Zeroizing custody for secret inputs and transients (framing tail,
		// snapshot accumulator).
		.package(url: "https://github.com/germ-network/swift-secret-bytes.git", from: "0.5.0"),
	],
	targets: [
		.target(
			name: "RAAE",
			dependencies: [
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "CryptoExtras", package: "swift-crypto"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
		.target(
			name: "SEAL",
			dependencies: [
				"RAAE",
				// The public API names `SymmetricKey` (CEK custody).
				.product(name: "Crypto", package: "swift-crypto"),
				// Snapshot accumulator custody.
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
		.testTarget(
			name: "RAAETests",
			dependencies: ["RAAE"],
			resources: [
				.copy("Vectors")
			]
		),
		.testTarget(
			name: "SEALTests",
			dependencies: ["SEAL"],
			resources: [
				.copy("Vectors")
			]
		),
	]
)
