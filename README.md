![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-curve448/actions/workflows/swift.yml/badge.svg)

# Swift-Curve448 - Swift bindings for Curve448

Swift-Curve448 is a Swift wrapper for OpenSSL's Curve448 implementation. It provides a simple and familiar API to perform key generation, signing, and signature verification.

## Usage
To add Swift-Curve448 as dependency to your Xcode project, select `File` > `Swift Packages` > `Add Package Dependency`, enter its repository URL: `https://github.com/Kingpin-Apps/swift-curve448.git` and import `SwiftCurve448`.

    ```swift
    dependencies: [
        .package(url: "https://github.com/Kingpin-Apps/swift-curve448.git", from: "0.0.1")
    ]
    ```

Then, to use it in your source code, add:

```swift
import SwiftCurve448
```


## Features
- [x] Private/Public key generation
- [x] Shared secret 
- [x] Signing
- [x] Signature verification
