![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-curve448/actions/workflows/swift.yml/badge.svg)

# Swift-Curve448 - Swift bindings for Curve448

Swift-Curve448 is a Swift wrapper for libgoldilocks' Curve448 implementation (Ed448 / X448), packaged via [swift-goldilocks](https://github.com/Kingpin-Apps/swift-goldilocks). It provides a simple and familiar API to perform key generation, signing, and signature verification.

## Installation
To add Swift-Curve448 as a dependency to your Xcode project, select `File` > `Add Package Dependencies…`, enter its repository URL, `https://github.com/Kingpin-Apps/swift-curve448.git`, and add `SwiftCurve448` to your target.

In a `Package.swift` file, add:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "0.3.1")
]
```

Then, to use it in your source code, add:

```swift
import SwiftCurve448
```

## Features
- [x] Private/Public key generation (Ed448 signing keys, X448 key agreement keys)
- [x] Shared secret (X448), with HKDF and X9.63 key derivation
- [x] Signing (Ed448, deterministic)
- [x] Signature verification

## Usage

### Sign and verify

```swift
let keyPair = Curve448.Signing.generateKeyPair()
let message = Data("Hello, World!".utf8)

let signature = try keyPair.privateKey.signature(for: message)  // 114 bytes
let isValid = keyPair.publicKey.isValidSignature(signature, for: message)
```

### Key agreement

```swift
let alice = Curve448.KeyAgreement.generateKeyPair()
let bob = Curve448.KeyAgreement.generateKeyPair()

let aliceSharedSecret = try alice.privateKey.sharedSecretFromKeyAgreement(with: bob.publicKey)
let bobSharedSecret = try bob.privateKey.sharedSecretFromKeyAgreement(with: alice.publicKey)
// aliceSharedSecret == bobSharedSecret
```

Don't use the shared secret as a key directly. Derive one with `hkdfDerivedSymmetricKey(using:salt:sharedInfo:outputByteCount:)` or `x963DerivedSymmetricKey(using:sharedInfo:outputByteCount:)`. These take a hash function such as `SHA256` and return a `SymmetricKey`, both from CryptoKit (or swift-crypto's `Crypto` module on platforms without CryptoKit).
