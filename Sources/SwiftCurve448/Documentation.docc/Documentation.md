# ``SwiftCurve448``

Swift implementation of the Curve448 elliptic curve. This library is a Swift wrapper around the [Curve448](https://cr.yp.to/ecdh.html) implementation from [SUPERCOP](https://bench.cr.yp.to/supercop.html).


## Overview

The library provides a Swift wrapper around the Curve448 implementation from SUPERCOP. The library provides the following functionalities:

- Generate a Curve448 keypair.
- Perform a Diffie-Hellman key exchange.
- Perform a Curve448 scalar multiplication.

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:
    
    ```swift
    dependencies: [
        .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "1.0.0")
    ]
    ```

### Manually

Download the latest release from the [releases page](https://github.com/Kingpin-Apps/swift-curve448.git). Drag and drop the `SwiftCurve448` folder into your project.

## Usage

### Generate a keypair

```swift
import SwiftCurve448

let keypair = Curve448.generateKeyPair()
```

### Perform a Diffie-Hellman key exchange

```swift
import SwiftCurve448

let aliceKeyPair = Curve448.generateKeyPair()
let bobKeyPair = Curve448.generateKeyPair()

let aliceSharedSecret = Curve448.diffieHellman(privateKey: aliceKeyPair.privateKey, publicKey: bobKeyPair.publicKey)
let bobSharedSecret = Curve448.diffieHellman(privateKey: bobKeyPair.privateKey, publicKey: aliceKeyPair.publicKey)

assert(aliceSharedSecret == bobSharedSecret)

```

### Perform a scalar multiplication

```swift
import SwiftCurve448

let keyPair = Curve448.generateKeyPair()
let scalar = Curve448.randomScalar()

let publicKey = Curve448.scalarMultiplyBase(scalar)
let sharedSecret = Curve448.scalarMultiply(scalar, keyPair.publicKey)

```

## License

This library is released under the MIT license. See [LICENSE](LICENSE) for details.

## Author

This library is developed and maintained by [Kingpin Apps](https://kingpinapps.com).

