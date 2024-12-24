// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftCurve448",
    platforms: [
      .iOS(.v14),
      .macOS(.v13),
      .watchOS(.v7),
      .tvOS(.v14),
    ],
    products: [
        .library(
            name: "SwiftCurve448",
            targets: ["SwiftCurve448"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.3.2000")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.8.3"))
    ],
    targets: [
        .target(
            name: "SwiftCurve448",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL-Package"),
                "CryptoSwift"
            ]),
        .testTarget(
            name: "SwiftCurve448Tests",
            dependencies: ["SwiftCurve448"]
        ),
    ]
)
