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
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.3.3000")),
        // Provides Crypto compatible APIs on Linux
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.15.1"),
    ],
    targets: [
        .target(
            name: "SwiftCurve448",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL-Package"),
                // Only link swift-crypto on Linux; on Apple platforms, CryptoKit is available.
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
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
