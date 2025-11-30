import Foundation
import OpenSSL

extension Curve448.Signing.PublicKey {
    // We do this to enable inlinability on these methods.
    @usableFromInline
    static let signatureByteCount = Curve448.Signing.signatureByteCount

    @inlinable
    func openSSLIsValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        if signature.count != Curve448.Signing.PublicKey.signatureByteCount {
            return false
        }

        // Both fields are potentially discontiguous, so we need to check and flatten them.
        switch (signature.regions.count, data.regions.count) {
        case (1, 1):
            // Both data protocols are secretly contiguous.
            return self.openSSLIsValidSignature(contiguousSignature: signature.regions.first!, contiguousData: data.regions.first!)
        case (1, _):
            // The data isn't contiguous: we make it so.
            return self.openSSLIsValidSignature(contiguousSignature: signature.regions.first!, contiguousData: Array(data))
        case (_, 1):
            // The signature isn't contiguous, make it so.
            return self.openSSLIsValidSignature(contiguousSignature: Array(signature), contiguousData: data.regions.first!)
        case (_, _):
            // Neither are contiguous.
            return self.openSSLIsValidSignature(contiguousSignature: Array(signature), contiguousData: Array(data))
        }
    }

    @inlinable
    func openSSLIsValidSignature<S: ContiguousBytes, D: ContiguousBytes>(contiguousSignature signature: S, contiguousData data: D) -> Bool {
        signature.withUnsafeBytes { signaturePointer in
            data.withUnsafeBytes { dataPointer in
                self.openSSLIsValidSignature(signaturePointer: signaturePointer, dataPointer: dataPointer)
            }
        }
    }

    // We need this factored out because self.keyBytes is not @usableFromInline, and so we can't see it.
    @usableFromInline
    func openSSLIsValidSignature(signaturePointer: UnsafeRawBufferPointer, dataPointer: UnsafeRawBufferPointer) -> Bool {
        precondition(signaturePointer.count == Curve448.Signing.PublicKey.signatureByteCount)
        
        guard rawRepresentation.count == 57 else {
            print("Error: Public key size is \(keyBytes.count) bytes, expected 57.")
            return false
        }

        // Create a context for the verification
        let ctx = EVP_MD_CTX_new()
        defer { EVP_MD_CTX_free(ctx) }

        // Create EVP_PKEY from the raw public key bytes
        let pkey = rawRepresentation.withUnsafeBytes { keyBytesPtr in
            EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED448,
                nil,
                keyBytesPtr.baseAddress,
                keyBytesPtr.count
            )
        }
        
        guard let validPkey = pkey else {
            let openSSLError = ERR_get_error()
            let errorString = String(cString: ERR_error_string(openSSLError, nil))
            print("Failed to create EVP_PKEY for public key: \(errorString)")
            return false
        }
        defer { EVP_PKEY_free(validPkey) }
        
        // Initialize EVP_DigestVerify
        if EVP_DigestVerifyInit(ctx, nil, nil, nil, validPkey) <= 0 {
            let openSSLError = ERR_get_error()
            let errorString = String(cString: ERR_error_string(openSSLError, nil))
            print("Failed to initialize EVP_DigestVerifyInit: \(errorString)")
            return false
        }

        // Perform the verification
        let rc = EVP_DigestVerify(
            ctx,
            signaturePointer.baseAddress,
            signaturePointer.count,
            dataPointer.baseAddress,
            dataPointer.count
        )

        if rc != 1 {
            let openSSLError = ERR_get_error()
            let errorString = String(cString: ERR_error_string(openSSLError, nil))
            print("Signature verification failed with EVP_DigestVerify: \(errorString)")
        }

        return rc == 1
    }
}

extension Curve448.Signing.PrivateKey {
    @inlinable
    func openSSLSignature<D: DataProtocol>(for data: D) throws -> Data {
        if data.regions.count == 1 {
            return try self.openSSLSignature(forContiguousData: data.regions.first!)
        } else {
            return try self.openSSLSignature(forContiguousData: Array(data))
        }
    }

    @inlinable
    func openSSLSignature<C: ContiguousBytes>(forContiguousData data: C) throws -> Data {
        try data.withUnsafeBytes {
            try self.openSSLSignature(forDataPointer: $0)
        }
    }

    @usableFromInline
    func openSSLSignature(forDataPointer dataPointer: UnsafeRawBufferPointer) throws -> Data {
        var signature = Data(repeating: 0, count: 114)  // Ed448 signature size

        // Create EVP_PKEY from raw private key
        let pkey = try self.key.withUnsafeBytes { seedPtr -> OpaquePointer? in
            guard seedPtr.count == 57 else {
                print("Error: Seed size is \(seedPtr.count) bytes, expected 57.")
                throw Curve448Error.incorrectKeySize("Seed must be 57 bytes for Ed448.")
            }

            let key = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_ED448,
                nil,
                seedPtr.baseAddress,
                seedPtr.count
            )

            if key == nil {
                let openSSLError = ERR_get_error()
                let errorString = String(cString: ERR_error_string(openSSLError, nil))
                print("Failed to create EVP_PKEY: \(errorString)")
            }
            return key
        }

        // Ensure the key was successfully created
        guard let validPkey = pkey else {
            let openSSLError = ERR_get_error()
            let errorString = String(cString: ERR_error_string(openSSLError, nil))
            throw Curve448Error.openSSLError("Could not create EVP_PKEY from raw private key: \(errorString)")
        }
        defer { EVP_PKEY_free(validPkey) }

        // Create EVP_MD_CTX for the signing operation
        let mdCtx = EVP_MD_CTX_new()
        guard let ctx = mdCtx else {
            throw Curve448Error.openSSLError("Could not create EVP_MD_CTX.")
        }
        defer { EVP_MD_CTX_free(ctx) }

        // Initialize the signing operation
        guard EVP_DigestSignInit(ctx, nil, nil, nil, validPkey) > 0 else {
            let openSSLError = ERR_get_error()
            let errorString = String(cString: ERR_error_string(openSSLError, nil))
            throw Curve448Error.openSSLError("Could not initialize EVP_DigestSignInit: \(errorString)")
        }

        // Perform the signing operation
        var signatureLength: Int = signature.count
        let rc: CInt = EVP_DigestSign(
            ctx,
            signature.withUnsafeMutableBytes { $0.baseAddress },
            &signatureLength,
            dataPointer.baseAddress,
            dataPointer.count
        )

        guard rc == 1 else {
            let openSSLError = ERR_get_error()
            let errorString = String(cString: ERR_error_string(openSSLError, nil))
            throw Curve448Error.openSSLError("Could not sign data with EVP_DigestSign: \(errorString)")
        }

        // Resize the signature to the actual length
        signature.count = signatureLength
        return signature
    }
}
