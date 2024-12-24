import Testing
@testable import SwiftCurve448

struct Ed448KeyTests {

    @Test func testPrivateKeyInitialization() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        #expect(privateKey != nil, "PrivateKey should initialize successfully.")
        
        let publicKey = privateKey.publicKey
        #expect(publicKey != nil, "PublicKey should be generated from PrivateKey.")
    }

    @Test func testPrivateKeyRawRepresentation() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let rawRepresentation = privateKey.rawRepresentation
        
        let reconstructedKey = try Curve448.Signing.PrivateKey(rawRepresentation: rawRepresentation)
        #expect(reconstructedKey.rawRepresentation == privateKey.rawRepresentation, "Reconstructed PrivateKey should match original raw representation.")
    }

    @Test func testPublicKeyRawRepresentation() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let rawRepresentation = publicKey.rawRepresentation
        
        #expect(rawRepresentation.count == Curve448.Signing.keyByteCount, "PublicKey raw representation size should match keyByteCount.")
        
        let reconstructedKey = try Curve448.Signing.PublicKey(rawRepresentation: rawRepresentation)
        #expect(reconstructedKey.rawRepresentation == rawRepresentation, "Reconstructed PublicKey should match original raw representation.")
    }
}
