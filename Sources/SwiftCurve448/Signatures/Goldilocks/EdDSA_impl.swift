import Foundation
import CGoldilocks

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

        let rc: ce_ed448_result = rawRepresentation.withUnsafeBytes { pubPtr in
            ce_ed448_verify(
                signaturePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                dataPointer.count == 0 ? nil : dataPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                dataPointer.count
            )
        }
        return rc == CE_ED448_SUCCESS
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

        // libgoldilocks pure-Ed448 signing. The 57-byte privkey and 57-byte
        // pubkey are both required by goldilocks_ed448_sign.
        guard self.key.count == 57 else {
            throw Curve448Error.incorrectKeySize("Seed must be 57 bytes for Ed448.")
        }
        let pubKey = self.publicKey.rawRepresentation
        signature.withUnsafeMutableBytes { sigPtr in
            self.key.withUnsafeBytes { privPtr in
                pubKey.withUnsafeBytes { pubPtr in
                    ce_ed448_sign(
                        sigPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        dataPointer.count == 0 ? nil : dataPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        dataPointer.count
                    )
                }
            }
        }
        return signature
    }
}
