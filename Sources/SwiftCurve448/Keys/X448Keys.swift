//
//  
//  Product: SwiftCurve448
//  Project: SwiftCurve448
//  Package: SwiftCurve448
//  
//  Created by Hareem Adderley on 23/12/2024 AT 11:24 AM
//  Copyright © 2024 Kingpin Apps. All rights reserved.
//
import Foundation

extension Curve448.KeyAgreement {
    static var keyByteCount: Int {
        return 56
    }
}

extension Curve448 {
    /// A mechanism used to create a shared secret between two users by
    /// performing X448 key agreement.
    public enum KeyAgreement {
        /// A Curve448 public key used for key agreement.
        public struct PublicKey: ECPublicKey {
            fileprivate var baseKey: Curve448PublicKeyImpl

            /// Creates a Curve448 public key for key agreement from a
            /// collection of bytes.
            ///
            /// - Parameters:
            /// - rawRepresentation: A raw representation of the key as a
            /// collection of contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                self.baseKey = try Curve448PublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            fileprivate init(baseKey: Curve448PublicKeyImpl) {
                self.baseKey = baseKey
            }

            /// A representation of the Curve448 public key as a collection of
            /// bytes.
            public var rawRepresentation: Data {
                return self.baseKey.rawRepresentation
            }

            var keyBytes: [UInt8] {
                return self.baseKey.keyBytes
            }

            private func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
                return try self.baseKey.keyBytes.withUnsafeBytes(body)
            }
        }

        /// A Curve25519 private key used for key agreement.
        public struct PrivateKey: DiffieHellmanKeyAgreement {
            fileprivate var baseKey: Curve448PrivateKeyImpl

            /// Creates a random Curve448 private key for key agreement.
            public init() {
                self.baseKey = Curve448PrivateKeyImpl()
            }

            /// The corresponding public key.
            public var publicKey: Curve448.KeyAgreement.PublicKey {
                return PublicKey(baseKey: self.baseKey.publicKey)
            }

            /// Creates a Curve448 private key for key agreement from a
            /// collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a
            /// collection of contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                self.baseKey = try Curve448PrivateKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Computes a shared secret with the provided public key from
            /// another party.
            ///
            /// - Parameters:
            ///   - publicKeyShare: The public key from another party to be
            /// combined with the private key from this user to create the
            /// shared secret.
            ///
            /// - Returns: The computed shared secret.
            public func sharedSecretFromKeyAgreement(with publicKeyShare: Curve448.KeyAgreement.PublicKey) throws -> SharedSecret {
                return try self.baseKey.sharedSecretFromKeyAgreement(with: publicKeyShare.baseKey)
            }
            
            /// The raw representation of the key as a collection of contiguous
            /// bytes.
            public var rawRepresentation: Data {
                return self.baseKey.rawRepresentation
            }

            var key: SecureBytes {
                return self.baseKey.key
            }
        }
    }
}
