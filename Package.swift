// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "tessera",
	platforms:[
		.macOS(.v15)
	],
	products: [
		.executable(
			 name:"tessera",
			 targets:[
				 "tessera"
			 ]
		 ),
		.library(
			name: "tessera-core",
			targets: ["tessera-core"]
		),
	],
	dependencies:[
		.package(url:"https://github.com/tannerdsilva/rawdog.git", "21.0.0"..<"22.0.0"),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", "14.0.0"..<"15.0.0"),
//		.package(url:"https://github.com/bwyma1/nostr-kit-swift", revision:"383708d31328ebecb806ace03b035203395198de"),
		.package(path:"../nostr-kit-swift"),
		.package(path:"../openpgp-kit-swift"),
		.package(url:"https://github.com/tannerdsilva/wireguard-swift", revision:"7245b1ee6ecae571318900c4343e97526c67868b"),

		.package(url:"https://github.com/apple/swift-nio.git", "2.81.0"..<"3.0.0"),
		.package(url:"https://github.com/apple/swift-log.git", "1.0.0"..<"2.0.0"),
		.package(url:"https://github.com/tannerdsilva/bedrock.git", "7.1.0"..<"8.0.0"),

		.package(url:"https://github.com/swift-server/swift-service-lifecycle.git", "2.6.3"..<"3.0.0"),
		.package(url:"https://github.com/apple/swift-argument-parser.git", "1.5.0"..<"2.0.0"),
	],
	targets: [
		.executableTarget(
			name: "tessera",
			dependencies:[
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"RAW_sha256", package:"rawdog"),
				.product(name:"QuickLMDB", package:"QuickLMDB"),
				
				.product(name:"NIO", package:"swift-nio"),
				.product(name:"ServiceLifecycle", package:"swift-service-lifecycle"),
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"wireguard-userspace-nio", package:"wireguard-swift"),
				.product(name: "openpgp-kit", package: "openpgp-kit-swift"),
				"tessera-core"
			],
			exclude: ["SmartCard.entitlements"]
		),
		.target(
			name: "tessera-core",
			dependencies:[
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"bedrock_fifo", package:"bedrock"),
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"RAW_sha256", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_ed25519", package:"rawdog"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"QuickLMDB", package:"QuickLMDB"),
				.product(name:"NIO", package:"swift-nio"),
				.product(name:"Logging", package:"swift-log"),
				.product(name:"wireguard-userspace-nio", package:"wireguard-swift"),
				.product(name:"nostr-kit-swift", package:"nostr-kit-swift"),
			]
		),
		.testTarget(
			name: "tessera-tests",
			dependencies: [
				"tessera-core"
			]
		),
	]
)
