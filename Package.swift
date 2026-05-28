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
        // Prebuilt OpenSSL xcframework for Apple platforms only.
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.3.3000")),
        // Provides Crypto compatible APIs on Linux
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.15.1"),
        // Shared libgoldilocks vendor — provides Ed448 + X448 + SHAKE on
        // platforms without a usable libcrypto (currently Android and Wasm).
        // Used to live in-tree as Sources/CEd448Vendored; pulled out so
        // swift-cose and other consumers can share the same C code.
        .package(url: "https://github.com/Kingpin-Apps/swift-goldilocks.git", from: "0.1.0"),
    ],
    targets: [
        // System libcrypto on Linux — provides the same `EVP_*`, `ERR_*` symbols
        // that `OpenSSL-Package` ships prebuilt on Apple. Sources import either
        // `OpenSSL` or `COpenSSL` via `#if canImport(...)`.
        .systemLibrary(
            name: "COpenSSL",
            pkgConfig: "libcrypto",
            providers: [
                .apt(["libssl-dev"]),
                .yum(["openssl-devel"]),
            ]
        ),
        .target(
            name: "SwiftCurve448",
            dependencies: [
                .product(
                    name: "OpenSSL",
                    package: "OpenSSL-Package",
                    condition: .when(platforms: [.iOS, .macOS, .watchOS, .tvOS, .visionOS, .macCatalyst])
                ),
                .target(
                    name: "COpenSSL",
                    condition: .when(platforms: [.linux])
                ),
                // libgoldilocks Ed448/X448 on platforms without libcrypto.
                .product(
                    name: "CGoldilocks",
                    package: "swift-goldilocks",
                    condition: .when(platforms: [.android, .wasi])
                ),
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
