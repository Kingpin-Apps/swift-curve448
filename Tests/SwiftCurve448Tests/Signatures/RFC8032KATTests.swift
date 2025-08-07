//
//  RFC8032KATTests.swift
//  SwiftCurve448
//
//  Created by Marcelo Santos on 07/08/2025.
//


import XCTest

import Foundation
import Testing
@testable import SwiftCurve448

class RFC8032KATTests {
    
    /// The test vector
    struct ED448TestVector: Decodable {
        var description: String
        var secKeyHex: String
        var pubKeyHex: String
        var messageHex: String
        var signatureHex: String
        
        enum CodingKeys: String, CodingKey {
            case description
            case secKeyHex = "secret_key"
            case pubKeyHex = "public_key"
            case messageHex = "message"
            case signatureHex = "signature"
        }
        
        var secretKeyBytes: Data { hexToBytes(hex: self.secKeyHex) }
        var publicKeyBytes: Data { hexToBytes(hex: self.pubKeyHex) }
        var messageBytes: Data { hexToBytes(hex: self.messageHex) }
        var signatureBytes: Data { hexToBytes(hex: self.signatureHex) }
    }
    
    // MARK: -
    
    /// Test using `ed448-signatures-KAT.json` test vectors from the [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032#section-7.4) ED448 Test vectors
    ///
    /// > Note: test "`-----1 octet (with context)`" was excluded because it requires injecting context into shared secret computation
    ///
    @Test
    func testRFCTestVectors() async throws {
        let katFile = try #require(
            Bundle.module.url(forResource: "ed448-signatures-KAT.json", withExtension: .none),
            "Should be able to generate file URL"
        )
        let decoder = JSONDecoder()
        let data = try Data(contentsOf: katFile)
        let tests = try decoder.decode([ED448TestVector].self, from: data)
        
        for test in tests {
            print("Testing \(test.description)")
            
            #expect(!test.signatureBytes.isEmpty, "Expected non-empty signature byte array")
            
            let privKey = try Curve448.Signing.PrivateKey(rawRepresentation: test.secretKeyBytes)
            #expect(privKey.publicKey.rawRepresentation.hexString == test.pubKeyHex, "ED448 Public Key generated should be as expected in RFC")
            let signature = try privKey.signature(for: test.messageBytes)
            #expect(signature.hexString == test.signatureHex)
        }
    }

}
