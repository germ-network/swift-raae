// swift-tools-version:6.0
import PackageDescription

let package = Package(
	name: "swift-raae",
	platforms: [
		.macOS(.v14),
		.iOS(.v17),
	],
	products: [
		.library(name: "RAAE", targets: ["RAAE"])
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
	],
	targets: [
		.target(
			name: "RAAE",
			dependencies: [
				.product(name: "Crypto", package: "swift-crypto")
			]
		),
		.testTarget(
			name: "RAAETests",
			dependencies: ["RAAE"],
			resources: [
				.copy("Vectors")
			]
		),
	]
)
