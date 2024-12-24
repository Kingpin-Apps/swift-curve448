import Foundation

extension Curve448.Signing {
    static var keyByteCount: Int {
        return 57
    }
}


extension Curve448 {
    /// A mechanism used to create or verify a cryptographic signature using Ed448.
    public enum Signing {
        /// A Curve448 private key used to create cryptographic signatures.
        public struct PrivateKey: ECPrivateKey {
            private var baseKey: Curve448.Signing.Curve448PrivateKeyImpl
            
            /// Creates a random Curve448 private key for signing.
            public init() {
                self.baseKey = Curve448.Signing.Curve448PrivateKeyImpl()
            }

            /// The corresponding public key.
            public var publicKey: PublicKey {
                return PublicKey(baseKey: self.baseKey.publicKey)
            }

            /// Creates a Curve448 private key for signing from a data
            /// representation.
            ///
            /// - Parameters:
            ///   - data: A representation of the key as contiguous bytes from
            /// which to create the key.
            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
                self.baseKey = try Curve448.Signing.Curve448PrivateKeyImpl(rawRepresentation: data)
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

        /// A Curve25519 public key used to verify cryptographic signatures.
        public struct PublicKey {
            private var baseKey: Curve448.Signing.Curve448PublicKeyImpl

            /// Creates a Curve25519 public key from a data representation.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A representation of the key as contiguous
            /// bytes from which to create the key.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                self.baseKey = try Curve448.Signing.Curve448PublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            fileprivate init(baseKey: Curve448.Signing.Curve448PublicKeyImpl) {
                self.baseKey = baseKey
            }

            /// A representation of the public key.
            public var rawRepresentation: Data {
                return self.baseKey.rawRepresentation
            }

            var keyBytes: [UInt8] {
                return self.baseKey.keyBytes
            }
        }
        
        /// Generates a new Curve448 key pair for signing.
        /// - Returns: The new key pair.
        public static func generateKeyPair() -> (publicKey: PublicKey, privateKey: PrivateKey) {
            let privateKey = PrivateKey()
            return (publicKey: privateKey.publicKey, privateKey: privateKey)
        }
    }
}
