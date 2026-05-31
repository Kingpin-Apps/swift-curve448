import Foundation
import CGoldilocks

// Ed448 signing keys, backed by libgoldilocks via the shared
// swift-goldilocks package on every platform.
extension Curve448.Signing {
    @usableFromInline
    struct Curve448PrivateKeyImpl {
        /* private but @usableFromInline */ var _privateKey: SecureBytes
        /* private but @usableFromInline */ @usableFromInline var _publicKey: [UInt8]

        @usableFromInline
        init() {
            // Generate a 57-byte random seed, derive the public key from it.
            var publicKey = Array(repeating: UInt8(0), count: Curve448.Signing.keyByteCount)
            let privateKey = SecureBytes(count: Curve448.Signing.keyByteCount)
            privateKey.withUnsafeBytes { privPtr in
                publicKey.withUnsafeMutableBytes { pubPtr in
                    ce_ed448_derive_public_key(
                        pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
            self._privateKey = privateKey
            self._publicKey = publicKey
        }

        @usableFromInline
        var publicKey: Curve448.Signing.Curve448PublicKeyImpl {
            Curve448PublicKeyImpl(self._publicKey)
        }

        var key: SecureBytes {
            self._privateKey
        }

        init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            var publicKey = Array(
                repeating: UInt8(0),
                count: Curve448.Signing.keyByteCount
            )

            // Copy the seed in, derive the public key.
            try data.withUnsafeBytes { seedPtr in
                guard seedPtr.count == Curve448.Signing.keyByteCount else {
                    throw Curve448Error.incorrectKeySize("Seed must be 57 bytes for Ed448, found \(seedPtr.count)")
                }
            }
            let privateKey = SecureBytes(bytes: data)
            privateKey.withUnsafeBytes { privPtr in
                publicKey.withUnsafeMutableBytes { pubPtr in
                    ce_ed448_derive_public_key(
                        pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }

            self._privateKey = privateKey
            self._publicKey = publicKey
        }

        @usableFromInline
        var rawRepresentation: Data {
            Data(self._privateKey.prefix(Curve448.Signing.keyByteCount))
        }
    }

    @usableFromInline
    struct Curve448PublicKeyImpl {
        @usableFromInline
        var keyBytes: [UInt8]

        @inlinable
        init<D: ContiguousBytes>(rawRepresentation: D) throws {
            self.keyBytes = try rawRepresentation.withUnsafeBytes { keyBytesPtr in
                guard keyBytesPtr.count == 57 else {
                    throw Curve448Error.incorrectKeySize("Public key must be 57 bytes for Ed448, found \(keyBytesPtr.count)")
                }
                return Array(keyBytesPtr)
            }
        }

        init(_ keyBytes: [UInt8]) {
            precondition(keyBytes.count == Curve448.Signing.keyByteCount)
            self.keyBytes = keyBytes
        }

        var rawRepresentation: Data {
            Data(self.keyBytes)
        }
    }
}
