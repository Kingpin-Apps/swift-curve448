# ``SwiftCurve448``

Ed448 signatures and X448 key agreement over Curve448, with a CryptoKit-style API.

## Overview

SwiftCurve448 wraps the Curve448 implementation from libgoldilocks, packaged by [swift-goldilocks](https://github.com/Kingpin-Apps/swift-goldilocks). Its API follows the shape of CryptoKit's `Curve25519` types, so it should feel familiar. The library lets you:

- Generate Ed448 signing keys and X448 key agreement keys.
- Perform an X448 key agreement and derive a symmetric key from the shared secret.
- Sign messages with Ed448.
- Verify Ed448 signatures.

Key derivation from a ``SharedSecret`` uses CryptoKit on Apple platforms and swift-crypto's `Crypto` module on other platforms.

## Installation

Add the package to the dependencies in your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "0.3.1")
]
```

Then add `SwiftCurve448` to your target's dependencies and import it:

```swift
import SwiftCurve448
```

## Usage

### Generate keys

Each `generateKeyPair()` call returns a `(publicKey, privateKey)` tuple. You can also create a private key directly and read its public key.

```swift
let signingKeyPair = Curve448.Signing.generateKeyPair()
let keyAgreementKeyPair = Curve448.KeyAgreement.generateKeyPair()

let privateKey = Curve448.Signing.PrivateKey()
let publicKey = privateKey.publicKey
```

### Perform a key agreement

```swift
let alice = Curve448.KeyAgreement.generateKeyPair()
let bob = Curve448.KeyAgreement.generateKeyPair()

let aliceSharedSecret = try alice.privateKey.sharedSecretFromKeyAgreement(with: bob.publicKey)
let bobSharedSecret = try bob.privateKey.sharedSecretFromKeyAgreement(with: alice.publicKey)

assert(aliceSharedSecret == bobSharedSecret)
```

Don't use the shared secret as a key directly. Derive a symmetric key from it instead:

```swift
let symmetricKey = aliceSharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: Data(),
    sharedInfo: Data("my app".utf8),
    outputByteCount: 32
)
```

`SHA256` and the returned `SymmetricKey` come from CryptoKit (or swift-crypto's `Crypto` module), so import that module too.

### Sign a message

Ed448 signatures are 114 bytes long and deterministic: the same key and message always give the same signature.

```swift
let keyPair = Curve448.Signing.generateKeyPair()
let message = Data("Hello, World!".utf8)

let signature = try keyPair.privateKey.signature(for: message)
```

### Verify a signature

```swift
let isValid = keyPair.publicKey.isValidSignature(signature, for: message)
assert(isValid)
```

## License

This library is released under the MIT license. It is developed and maintained by [Kingpin Apps](https://kingpinapps.com).

## Topics

### Signing

- ``Curve448/Signing``
- ``Curve448/Signing/PrivateKey``
- ``Curve448/Signing/PublicKey``

### Key agreement

- ``Curve448/KeyAgreement``
- ``Curve448/KeyAgreement/PrivateKey``
- ``Curve448/KeyAgreement/PublicKey``
- ``SharedSecret``
- ``DiffieHellmanKeyAgreement``

### Namespaces and errors

- ``Curve448``
- ``Curve448Error``
