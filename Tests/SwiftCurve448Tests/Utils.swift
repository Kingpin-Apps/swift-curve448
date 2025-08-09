//
//  Utils.swift
//  SwiftCurve448
//
//  Created by Marcelo Santos on 07/08/2025.
//
//
// Convenient functions / objects / extensions 

import Foundation
@testable import SwiftCurve448

/// Converts a string hexadecimal into an array of bytes
/// - Parameter hex:a string containing the hexadecimals to be converted
/// - Returns: the array of bytes extracted from **hex**
func hexToBytes(hex: String) -> Data {
    if let dataBytes = try? Data(hexString: hex) { return dataBytes }
    return Data()
}
