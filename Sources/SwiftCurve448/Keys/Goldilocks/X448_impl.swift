import Foundation
import CGoldilocks

extension Curve448.KeyAgreement {
    @usableFromInline
    static let keySizeBytes = 56

    @usableFromInline
    struct Curve448PublicKeyImpl {
        @usableFromInline
        var keyBytes: [UInt8]

        @inlinable
        init<D: ContiguousBytes>(rawRepresentation: D) throws {
            self.keyBytes = try rawRepresentation.withUnsafeBytes { dataPtr in
                guard dataPtr.count == Curve448.KeyAgreement.keySizeBytes else {
                    throw Curve448Error.incorrectKeySize("Curve448 public keys must be \(Curve448.KeyAgreement.keySizeBytes) bytes")
                }

                return Array(dataPtr)
            }
        }

        @usableFromInline
        init(_ keyBytes: [UInt8]) {
            self.keyBytes = keyBytes
        }

        @usableFromInline
        var rawRepresentation: Data {
            Data(self.keyBytes)
        }
    }

    @usableFromInline
    struct Curve448PrivateKeyImpl {
        var key: SecureBytes

        @usableFromInline
        var publicKey: Curve448PublicKeyImpl

        init() {
            // Generate 56 random bytes, derive the X448 public key.
            var publicKey = Array(repeating: UInt8(0), count: Curve448.KeyAgreement.keySizeBytes)
            let privateKey = SecureBytes(count: Curve448.KeyAgreement.keySizeBytes)
            privateKey.withUnsafeBytes { privPtr in
                publicKey.withUnsafeMutableBytes { pubPtr in
                    ce_x448_derive_public_key(
                        pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
            self.key = privateKey
            self.publicKey = .init(publicKey)
        }

        init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            var publicKey = Array(
                repeating: UInt8(0),
                count: Curve448.KeyAgreement.keyByteCount
            )

            // Validate the 56-byte scalar up front, then derive the public key.
            try data.withUnsafeBytes { seedPtr in
                guard seedPtr.count == Curve448.KeyAgreement.keySizeBytes else {
                    throw Curve448Error.incorrectKeySize("Curve448 private keys must be \(Curve448.KeyAgreement.keySizeBytes) bytes")
                }
            }
            let privateKey = SecureBytes(bytes: data)
            privateKey.withUnsafeBytes { privPtr in
                publicKey.withUnsafeMutableBytes { pubPtr in
                    ce_x448_derive_public_key(
                        pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }

            self.key = privateKey
            self.publicKey = .init(publicKey)
        }

        @usableFromInline
        func sharedSecretFromKeyAgreement(with publicKeyShare: Curve448PublicKeyImpl) throws -> SharedSecret {
            // X448 ECDH: scalar × peer_pubkey → 56-byte shared secret.
            var sharedBytes = [UInt8](repeating: 0, count: Curve448.KeyAgreement.keySizeBytes)
            let rc = sharedBytes.withUnsafeMutableBytes { sharedPtr -> ce_ed448_result in
                key.withUnsafeBytes { scalarPtr in
                    publicKeyShare.keyBytes.withUnsafeBufferPointer { peerPtr in
                        ce_x448_shared_secret(
                            sharedPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            scalarPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            peerPtr.baseAddress!
                        )
                    }
                }
            }
            guard rc == CE_ED448_SUCCESS else {
                throw Curve448Error.keyAgreementFailure("X448 key agreement returned an all-zero (small-subgroup) shared secret.")
            }
            let sharedSecret = SecureBytes(bytes: sharedBytes)
            return SharedSecret(ss: sharedSecret)
        }

        @usableFromInline
        var rawRepresentation: Data {
            Data(self.key)
        }

        /// Validates whether the passed x448 key representation is valid.
        /// - Parameter rawRepresentation: The provided key representation. Expected to be a valid 32-bytes private key.
        static func validateX448PrivateKeyData(rawRepresentation: UnsafeRawBufferPointer) throws {
            guard rawRepresentation.count == Curve448.KeyAgreement.keySizeBytes else {
                throw Curve448Error.incorrectKeySize("Curve448 private keys must be \(Curve448.KeyAgreement.keySizeBytes) bytes")
            }
        }
    }
}
