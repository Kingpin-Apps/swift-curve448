import Foundation

protocol ECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws
    var rawRepresentation: Data { get }
}

protocol ECPrivateKey {
    associatedtype PK
    var publicKey: PK { get }
}

