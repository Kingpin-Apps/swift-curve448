import Testing
@testable import SwiftCurve448

struct X448KeyTests {
    
    @Test
    func testGenerateKeyPair() async throws {
        let keyPair = Curve448.KeyAgreement.generateKeyPair()
        
        #expect(!keyPair.privateKey.rawRepresentation.isEmpty, "Private key should not be empty")
        #expect(!keyPair.publicKey.rawRepresentation.isEmpty, "Public key should not be empty")
        
        #expect(keyPair.publicKey.rawRepresentation.count == 56, "Public key should be 56 bytes long.")
        #expect(keyPair.privateKey.rawRepresentation.count == 56, "Private key should be 56 bytes long.")
    }

    @Test
    func testX448PrivateKeyInitialization() async throws {
        let privateKey = Curve448.KeyAgreement.PrivateKey()
        #expect(!privateKey.rawRepresentation.isEmpty, "X448 PrivateKey should initialize successfully.")
        
        let publicKey = privateKey.publicKey
        #expect(!publicKey.rawRepresentation.isEmpty, "X448 PublicKey should be generated from PrivateKey.")
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
        
        #expect(!sharedSecretA.ss.isEmpty, "Shared Secret from X448 should not be empty")
        #expect(!sharedSecretB.ss.isEmpty, "Shared Secret from X448 should not be empty")
        #expect(sharedSecretA == sharedSecretB,
               "Shared secrets from X448 key agreement should match between two parties.")
    }
    
    // MARK: - RFC KAT
    
    // Source: [RFC 7748 - Section 6.2 Test vector](https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.2)
    ///
    /// Alice and Bob generate 56 random bytes and calculate K_A = X448(a, 5)
    /// or K_B = X448(b, 5), where 5 is the u-coordinate of the base point and is encoded as a byte with value 5, followed by 55 zero bytes.
    /// As with X25519, both sides MAY check, without leaking extra information about the value of K,
    ///whether the resulting shared K is the all-zero value and abort if so.
    @Test
    func testX448KeyAgreementKATFromRFC() throws {
        // Alice's private key, a:
        let aliceSk = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        // Bob's private key, b:
        let bobSk = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        // Alice's public key, X448(a, 5):
        let aliceExpectedPk = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        // Bob's public key, X448(b, 5):
        let bobExpectedPk = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        // Their shared secret, K:
        let expectedSharedSecret = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        
        let aliceSkBytes = hexToBytes(hex: aliceSk)
        let bobSkBytes = hexToBytes(hex: bobSk)
        #expect(!aliceSkBytes.isEmpty)
        
        
        let aliceX448 = try Curve448.KeyAgreement.PrivateKey(rawRepresentation: aliceSkBytes)
        let bobX448 = try Curve448.KeyAgreement.PrivateKey(rawRepresentation: bobSkBytes)
        #expect(aliceX448.publicKey.rawRepresentation.hexString == aliceExpectedPk, "X448 Public Key should be as expected in RFC")
        #expect(bobX448.publicKey.rawRepresentation.hexString == bobExpectedPk, "X448 Public Key should be as expected in RFC")
        
        let sharedSecret = try aliceX448.sharedSecretFromKeyAgreement(with: bobX448.publicKey)
        #expect(sharedSecret.ss.hexString == expectedSharedSecret, "Shared Secret computed should be as expected in RFC")
    }
}
