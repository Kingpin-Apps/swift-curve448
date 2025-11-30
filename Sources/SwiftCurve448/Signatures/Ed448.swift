#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif
import Foundation

protocol DigestValidator {
    associatedtype Signature
    func isValidSignature<D: Digest>(_ signature: Signature, for digest: D) -> Bool
}

protocol DataValidator {
    associatedtype Signature
    func isValidSignature<D: DataProtocol>(_ signature: Signature, for signedData: D) -> Bool
}

extension Curve448.Signing {
    static var signatureByteCount: Int {
        return 114
    }
}

extension Curve448.Signing.PublicKey: DataValidator {
    typealias Signature = Data
    
    /// Verifies an EdDSA signature over Curve448.
    ///
    /// - Parameters:
    ///   - signature: The signature to check against the given data.
    ///   - data: The data covered by the signature.
    ///
    /// - Returns: A Boolean value that’s `true` when the signature is valid for
    /// the given data.
    public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        return self.openSSLIsValidSignature(signature, for: data)
    }
}

extension Curve448.Signing.PrivateKey: Signer {
    /// Generates an EdDSA signature over Curve448.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///
    /// - Returns: The signature for the data. Although not required by [RFC
    /// 8032](https://tools.ietf.org/html/rfc8032), which describes the
    /// Edwards-Curve Digital Signature Algorithm (EdDSA), the CryptoKit
    /// implementation of the algorithm employs randomization to generate a
    /// different signature on every call, even for the same data and key, to
    /// guard against side-channel attacks.
    public func signature<D: DataProtocol>(for data: D) throws -> Data {
        return try self.openSSLSignature(for: data)
    }
}
