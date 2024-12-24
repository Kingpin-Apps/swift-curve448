# ``SwiftCurve448``

Swift-Curve448 is a Swift wrapper for OpenSSL's Curve448 implementation. It provides a simple and familiar API to perform key generation, signing, and signature verification.


## Overview

The library provides a Swift wrapper around the Curve448 implementation from OpenSSL. The library provides the following functionalities:

- Generate a Curve448 keypair.
- Perform a key exchange.
- Sign messages.
- Verify signatures.

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

let signingKeyPair = Curve448.Signing.generateKeyPair()

let keyAgreementKeyPair = Curve448.KeyAgreement.generateKeyPair()
```

### Perform a Key Agreement
    
```swift
import SwiftCurve448

let aliceKeyPair = Curve448.KeyAgreement.generateKeyPair()
let bobKeyPair = Curve448.KeyAgreement.generateKeyPair()

let aliceSharedSecret = aliceKeyPair.privateKey.sharedSecret(with: bobKeyPair.publicKey)
let bobSharedSecret = bobKeyPair.privateKey.sharedSecret(with: aliceKeyPair.publicKey)

assert(aliceSharedSecret == bobSharedSecret)
```

### Sign a message
    
```swift
import SwiftCurve448

let keyPair = Curve448.Signing.generateKeyPair()
let message = "Hello, World!".data(using: .utf8)!
let signature = keyPair.privateKey.sign(message)
```

### Verify a signature
        
```swift
import SwiftCurve448

let keyPair = Curve448.Signing.generateKeyPair()
let message = "Hello, World!".data(using: .utf8)!
let signature = keyPair.privateKey.sign(message)

let isValid = keyPair.publicKey.verify(signature, for: message)
assert(isValid)
```



## License

This library is released under the MIT license. See [LICENSE](LICENSE) for details.

## Author

This library is developed and maintained by [Kingpin Apps](https://kingpinapps.com).

