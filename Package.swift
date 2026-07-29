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
		// 3.x and 4.x both work: this package uses only SymmetricKey, HKDF,
		// AES.GCM, ChaChaPoly and _CryptoExtras' AES-GCM-SIV, none of which
		// changed across the major bump. Capping at 4 kept adopters already on
		// swift-crypto 4 from resolving at all.
		.package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0")
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
