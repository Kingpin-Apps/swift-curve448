import Foundation

/// `Curve448Error` is an enumeration of errors that can be thrown by the Curve448Error library.
public enum Curve448Error: Error {
    case genericError(String)
    case incorrectKeySize(String)
    case keyAgreementFailure(String)
    case keyGenerationFailed(String)
    case notImplemented(String)
    @available(*, deprecated, message: "OpenSSL is no longer used; this case is retained for API compatibility and will be removed in a future major release")
    case openSSLError(String)
    case valueError(String)
}
