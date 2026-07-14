// swift-tools-version:6.0
import PackageDescription

let package = Package(
	name: "swift-raae",
	platforms: [
		.macOS(.v14),
		.iOS(.v17),
	],
	products: [
		// The granular core: byte-exact primitives for implementers and vector tooling.
		.library(name: "RAAE", targets: ["RAAE"]),
		// The high-level engine (recommended): spec-shaped lifecycle API over the core.
		.library(name: "SEAL", targets: ["SEAL"]),
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
	],
	targets: [
		.target(
			name: "RAAE",
			dependencies: [
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "_CryptoExtras", package: "swift-crypto"),
			]
		),
		.target(
			name: "SEAL",
			dependencies: ["RAAE"]
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
