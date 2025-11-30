import Foundation
import OpenSSL

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
            // Create a new context for Ed448 key generation
            let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nil)
            defer { EVP_PKEY_CTX_free(ctx) }
            
            // Initialize key generation
            guard EVP_PKEY_keygen_init(ctx) == 1 else {
                fatalError("Failed to initialize X448 key generation.")
            }
            
            var pkey: OpaquePointer?
            
            // Generate the key
            guard EVP_PKEY_keygen(ctx, &pkey) == 1 else {
                fatalError("Failed to generate X448 key.")
            }
            defer { EVP_PKEY_free(pkey) }
            
            var publicKey = Array(repeating: UInt8(0), count: Curve448.KeyAgreement.keySizeBytes)

            let privateKey = SecureBytes(unsafeUninitializedCapacity: 113) { privateKeyPtr, privateKeyBytes in
                privateKeyBytes = 113
                var publicKeyLength = 56
                let _ = publicKey.withUnsafeMutableBytes { publicKeyPtr in
                    guard let publicKeyRawPtr = publicKeyPtr.baseAddress else {
                        return
                    }
                    guard EVP_PKEY_keygen(ctx, privateKeyPtr) == 1 else {
                        return
                    }
                    EVP_PKEY_keygen(ctx, privateKeyPtr)
                    
                    EVP_PKEY_get_raw_private_key(
                        pkey,
                        privateKeyPtr,
                        &privateKeyBytes
                    )
                    EVP_PKEY_get_raw_public_key(
                        pkey,
                        publicKeyRawPtr,
                        &publicKeyLength)
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
            
            let privateKey = try SecureBytes(unsafeUninitializedCapacity: 112) { privateKeyPtr, privateKeyBytes in
                privateKeyBytes = 112
                var publicKeyLength = 57
                
                let pkey = data.withUnsafeBytes { seedPtr -> OpaquePointer? in
                    
                    return EVP_PKEY_new_raw_private_key(
                        EVP_PKEY_X448,
                        nil,
                        seedPtr.baseAddress,
                        seedPtr.count
                    )
                }
                
                // Ensure the key was successfully created
                guard let validPkey = pkey else {
                    let openSSLError = ERR_get_error()
                    let errorString = String(cString: ERR_error_string(openSSLError, nil))
                    throw Curve448Error.openSSLError("Could not create EVP_PKEY from raw private key: \(errorString)")
                }
                defer { EVP_PKEY_free(validPkey) }

                // Extract the private key safely
                let privateKeyResult = publicKey.withUnsafeMutableBytes { publicKeyPtr in
                    EVP_PKEY_get_raw_private_key(
                        pkey,
                        privateKeyPtr,
                        &privateKeyBytes
                    )
                }

                // Extract the public key safely
                let publicKeyResult = publicKey.withUnsafeMutableBytes { publicKeyPtr in
                    EVP_PKEY_get_raw_public_key(
                        validPkey,
                        publicKeyPtr.baseAddress,
                        &publicKeyLength)
                }
                
                // If key extraction fails, throw an error
                guard privateKeyResult == 1 && publicKeyResult == 1 else {
                    let openSSLError = ERR_get_error()
                    let errorString = String(cString: ERR_error_string(openSSLError, nil))
                    throw Curve448Error.openSSLError("Could not extract key: \(errorString)")
                }
            }
            
            self.key = privateKey
            self.publicKey = .init(publicKey)
        }

        @usableFromInline
        func sharedSecretFromKeyAgreement(with publicKeyShare: Curve448PublicKeyImpl) throws -> SharedSecret {
            var ctx: OpaquePointer?
            var pkey: OpaquePointer?
            var peerkey: OpaquePointer?

            defer {
                EVP_PKEY_CTX_free(ctx)
                EVP_PKEY_free(pkey)
                EVP_PKEY_free(peerkey)
            }
            
            // Initialize private key from raw data
            key.withUnsafeBytes { keyPtr in
                pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, nil, keyPtr.baseAddress, key.count)
            }
            guard pkey != nil else {
                throw Curve448Error.keyAgreementFailure("Failed to create private key.")
            }

            // Initialize peer public key
            peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, nil, publicKeyShare.keyBytes, publicKeyShare.keyBytes.count)
            guard peerkey != nil else {
                throw Curve448Error.keyAgreementFailure("Failed to create peer public key.")
            }

            // Set up key derivation context
            ctx = EVP_PKEY_CTX_new(pkey, nil)
            guard ctx != nil else {
                throw Curve448Error.keyAgreementFailure("Failed to initialize context.")
            }
            
            // Initialize key derivation
            guard EVP_PKEY_derive_init(ctx) == 1 else {
                throw Curve448Error.keyAgreementFailure("Key derivation initialization failed.")
            }
            
            // Set the peer public key for derivation
            guard EVP_PKEY_derive_set_peer(ctx, peerkey) == 1 else {
                throw Curve448Error.keyAgreementFailure("Failed to set peer public key.")
            }

            // Determine the required buffer length
            var secretLength: size_t = 0
            guard EVP_PKEY_derive(ctx, nil, &secretLength) == 1 else {
                throw Curve448Error.keyAgreementFailure("Failed to determine secret length.")
            }
            
            // Perform key agreement to derive shared secret
            let sharedSecret = SecureBytes(unsafeUninitializedCapacity: secretLength) { secretPointer, secretSize in
                let result = EVP_PKEY_derive(ctx, secretPointer, &secretLength)
                
                guard result == 1 else {
                    return
                }
                // set the underlying size upon sucessfully generating the shared secret
                secretSize = secretLength
            }

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
