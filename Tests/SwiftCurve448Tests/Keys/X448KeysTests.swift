import Testing
@testable import SwiftCurve448

struct X448KeyTests {
    
    @Test
    func testGenerateKeyPair() async throws {
        let keyPair = Curve448.KeyAgreement.generateKeyPair()
        
        #expect(keyPair.privateKey != nil, "Private key should not be nil.")
        #expect(keyPair.publicKey != nil, "Public key should not be nil.")
        
        #expect(keyPair.publicKey.rawRepresentation.count == 56, "Public key should be 56 bytes long.")
        #expect(keyPair.privateKey.rawRepresentation.count == 56, "Private key should be 56 bytes long.")
    }

    @Test
    func testX448PrivateKeyInitialization() async throws {
        let privateKey = Curve448.KeyAgreement.PrivateKey()
        #expect(privateKey != nil, "X448 PrivateKey should initialize successfully.")
        
        let publicKey = privateKey.publicKey
        #expect(publicKey != nil, "X448 PublicKey should be generated from PrivateKey.")
    }

    @Test
    func testX448PrivateKeyRawRepresentation() async throws {
        let privateKey = Curve448.KeyAgreement.PrivateKey()
        let rawRepresentation = privateKey.rawRepresentation
        
        let reconstructedKey = try Curve448.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        
        #expect(reconstructedKey.rawRepresentation == privateKey.rawRepresentation,
               "Reconstructed X448 PrivateKey should match original raw representation.")
    }

    @Test
    func testX448PublicKeyRawRepresentation() async throws {
        let privateKey = Curve448.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let rawRepresentation = publicKey.rawRepresentation
        
        #expect(rawRepresentation.count == Curve448.KeyAgreement.keyByteCount,
               "X448 PublicKey raw representation size should match keyByteCount.")
        
        let reconstructedKey = try Curve448.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
        
        #expect(reconstructedKey.rawRepresentation == rawRepresentation,
               "Reconstructed X448 PublicKey should match original raw representation.")
    }

    @Test
    func testX448KeyAgreement() async throws {
        let privateKeyA = Curve448.KeyAgreement.PrivateKey()
        let privateKeyB = Curve448.KeyAgreement.PrivateKey()
        
        let sharedSecretA = try privateKeyA.sharedSecretFromKeyAgreement(with: privateKeyB.publicKey)
        let sharedSecretB = try privateKeyB.sharedSecretFromKeyAgreement(with: privateKeyA.publicKey)
        
        #expect(sharedSecretA == sharedSecretB,
               "Shared secrets from X448 key agreement should match between two parties.")
    }
}
