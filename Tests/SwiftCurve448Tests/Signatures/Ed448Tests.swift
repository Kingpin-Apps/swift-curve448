import Testing
import Foundation
@testable import SwiftCurve448

struct Ed448SignaturesTests {

    // MARK: - Signing Tests
    
    @Test
    func testEd448SignatureGeneration() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let message = "Test message".data(using: .utf8)!
        
        let signature = try privateKey.signature(for: message)
        
        #expect(signature.count == Curve448.Signing.signatureByteCount,
               "Ed448 signature should be 114 bytes long.")
    }
    
    @Test
    func testEd448SigningConsistency() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let message = "Consistent message".data(using: .utf8)!
        
        let signature1 = try privateKey.signature(for: message)
        let signature2 = try privateKey.signature(for: message)
        
        #expect(signature1 == signature2,
               "Ed448 should generate the same signature for the same data (deterministic signing).")
    }
    
    // MARK: - Verification Tests
    
    @Test
    func testEd448SignatureVerification() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Verification message".data(using: .utf8)!
        
        let signature = try privateKey.signature(for: message)
        
        let isValid = publicKey.isValidSignature(signature, for: message)
        
        #expect(isValid == true, "Valid Ed448 signature should verify correctly.")
    }
    
    @Test
    func testEd448SignatureVerificationFailure() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Valid message".data(using: .utf8)!
        let tamperedMessage = "Tampered message".data(using: .utf8)!
        
        let signature = try privateKey.signature(for: message)
        
        let isValid = publicKey.isValidSignature(signature, for: tamperedMessage)
        
        #expect(isValid == false, "Ed448 signature should not verify against tampered data.")
    }
    
    @Test
    func testEd448InvalidSignature() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Message for invalid signature".data(using: .utf8)!
        
        let invalidSignature = Data(repeating: 0, count: Curve448.Signing.signatureByteCount)
        
        let isValid = publicKey.isValidSignature(invalidSignature, for: message)
        
        #expect(isValid == false, "Ed448 should reject invalid signatures.")
    }
    
    // MARK: - Edge Cases
    
    @Test
    func testEd448ShortSignature() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Short signature test".data(using: .utf8)!
        
        let shortSignature = Data(repeating: 0, count: Curve448.Signing.signatureByteCount - 1)
        
        let isValid = publicKey.isValidSignature(shortSignature, for: message)
        
        #expect(isValid == false, "Ed448 should reject signatures that are too short.")
    }
    
    @Test
    func testEd448LongSignature() async throws {
        let privateKey = Curve448.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Long signature test".data(using: .utf8)!
        
        let longSignature = Data(repeating: 0, count: Curve448.Signing.signatureByteCount + 1)
        
        let isValid = publicKey.isValidSignature(longSignature, for: message)
        
        #expect(isValid == false, "Ed448 should reject signatures that are too long.")
    }
}
