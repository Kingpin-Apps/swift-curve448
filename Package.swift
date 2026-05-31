// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftCurve448",
    platforms: [
      .iOS(.v14),
      .macOS(.v13),
      .watchOS(.v9),
      .tvOS(.v14),
      .visionOS(.v1)
    ],
    products: [
        .library(
            name: "SwiftCurve448",
            targets: ["SwiftCurve448"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-goldilocks.git", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: "SwiftCurve448",
            dependencies: [
                // libgoldilocks Ed448/X448 on every platform.
                .product(name: "CGoldilocks", package: "swift-goldilocks"),
                // Only link swift-crypto on Linux, Android, and Wasm; on Apple
                // platforms, CryptoKit is available.
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux, .android, .wasi])
                ),
            ]),
        .testTarget(
            name: "SwiftCurve448Tests",
            dependencies: ["SwiftCurve448"],
            resources: [
                .process("Resources")
            ]
        ),
    ]
)
