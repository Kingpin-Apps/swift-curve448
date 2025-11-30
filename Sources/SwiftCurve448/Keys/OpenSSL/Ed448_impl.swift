import Foundation
import OpenSSL

// For signing and verifying, we use OpenSSL's Ed448, not the X448 stuff.
extension Curve448.Signing {
    @usableFromInline
    struct Curve448PrivateKeyImpl {
        /* private but @usableFromInline */ var _privateKey: SecureBytes
        /* private but @usableFromInline */ @usableFromInline var _publicKey: [UInt8]

        @usableFromInline
        init() {
            // Create a new context for Ed448 key generation
            let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, nil)
            defer { EVP_PKEY_CTX_free(ctx) }
            
            // Initialize key generation
            guard EVP_PKEY_keygen_init(ctx) == 1 else {
                fatalError("Failed to initialize Ed448 key generation.")
            }
            
            var pkey: OpaquePointer?
            
            // Generate the key
            guard EVP_PKEY_keygen(ctx, &pkey) == 1 else {
                fatalError("Failed to generate Ed448 key.")
            }
            defer { EVP_PKEY_free(pkey) }
            
            var publicKey = Array(
                repeating: UInt8(0),
                count: Curve448.Signing.keyByteCount
            )
            
            let privateKey = SecureBytes(unsafeUninitializedCapacity: 113) { privateKeyPtr, privateKeyBytes in
                privateKeyBytes = Curve448.Signing.keyByteCount * 2
                var publicKeyLength = Curve448.Signing.keyByteCount
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
            
            let privateKey = try SecureBytes(unsafeUninitializedCapacity: Curve448.Signing.keyByteCount * 2) { privateKeyPtr, privateKeyBytes in
                privateKeyBytes = Curve448.Signing.keyByteCount * 2
                var publicKeyLength = Curve448.Signing.keyByteCount
                
                let pkey = try data.withUnsafeBytes { seedPtr -> OpaquePointer? in
                    guard seedPtr.count == Curve448.Signing.keyByteCount else {
                        throw Curve448Error.incorrectKeySize("Seed must be 57 bytes for Ed448, found \(seedPtr.count)")
                    }
                    
                    return EVP_PKEY_new_raw_private_key(
                        EVP_PKEY_ED448,
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
                    throw Curve448Error.incorrectKeySize("Seed must be 56 bytes")
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
