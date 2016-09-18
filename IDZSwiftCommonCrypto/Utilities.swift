//
//  Utilities.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/21/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

///
/// Converts a single hexadecimal digit encoded as a Unicode Scalar to it's corresponding value.
///
/// - parameter c: A Unicode scalar in the set 0..9a..fA..F
/// - returns: the hexadecimal value of the digit
///
func convertHexDigit(_ c : UnicodeScalar) -> UInt8
{
    switch c {
        case UnicodeScalar("0")...UnicodeScalar("9"): return UInt8(c.value - UnicodeScalar("0").value)
        case UnicodeScalar("a")...UnicodeScalar("f"): return UInt8(c.value - UnicodeScalar("a").value + UInt32(0xa))
        case UnicodeScalar("A")...UnicodeScalar("F"): return UInt8(c.value - UnicodeScalar("A").value + UInt32(0xa))
        default: fatalError("convertHexDigit: Invalid hex digit")
    }
}

///
/// Converts a string of hexadecimal digits to a Swift array.
///
/// - parameter s: the hex string (must contain an even number of digits)
/// - returns: a Swift array
///
public func arrayFromHexString(_ s : String) -> [UInt8]
{
    var g = s.unicodeScalars.makeIterator()
    var a : [UInt8] = []
    while let msn = g.next()
    {
        if let lsn = g.next()
        {
            a += [ (convertHexDigit(msn) << 4 | convertHexDigit(lsn)) ]
        }
        else
        {
            fatalError("arrayFromHexString: String must contain even number of characters")
        }
    }
    return a
}

///
/// Converts a Swift UTF-8 String to a Swift array.
///
/// - parameter s: the string
/// - returns: a Swift array
///
public func arrayFromString(_ s : String) -> [UInt8]
{
    let array = [UInt8](s.utf8)
    return array
}

///
/// Converts a string of hexadecimal digits to an `NSData` object.
///
/// - parameter s: the hex string (must contain an even number of digits)
/// - returns: an NSData object
///
public func dataFromHexString(_ s : String) -> Data
{
    let a = arrayFromHexString(s)
    return Data(bytes: UnsafePointer<UInt8>(a), count:a.count)
}

///
/// Converts a Swift array to an `NSData` object.
///
/// - parameter a: the Swift array
/// - returns: an NSData object
///
public func dataFromByteArray(_ a : [UInt8]) -> Data
{
    return Data(bytes: UnsafePointer<UInt8>(a), count:a.count)
}

///
/// Converts a Swift array to a string of hexadecimal digits.
///
/// - parameter a: the Swift array
/// - parameter uppercase: if true use uppercase for letter digits, lowercase otherwise
/// - returns: a Swift string
///
public func hexStringFromArray(_ a : [UInt8], uppercase : Bool = false) -> String
{
    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", +)
}

///
/// Converts a Swift array to an `NSString` object.
///
/// - parameter a: the Swift array
/// - parameter uppercase: if true use uppercase for letter digits, lowercase otherwise
/// - returns: an `NSString` object
///
//public func hexNSStringFromArray(_ a : [UInt8], uppercase : Bool = false) -> NSString
//{
//    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", +)
//}

///
/// Converts a Swift array to a Swift `String` containing a comma separated list of bytes.
/// This is used to generate test data programmatically.
///
/// - parameter a: the Swift array
/// - returns: a Swift string
///
public func hexListFromArray(_ a : [UInt8]) -> String
{
    return a.map() { String(format:"0x%02x, ", $0) }.reduce("", +)    
}

///
/// Zero pads a Swift array such that it is an integral number of `blockSizeinBytes` long.
///
/// - parameter a: the Swift array
/// - parameter blockSizeInBytes: the block size in bytes (cunningly enough!)
/// - returns: a Swift string
///
public func zeroPad(_ a: [UInt8], _ blockSize: Int) -> [UInt8] {
    let pad = blockSize - (a.count % blockSize)
    guard pad != 0 else { return a }
    return a + Array<UInt8>(repeating: 0, count: pad)
}

///
/// Zero pads a Swift string (after UTF8 conversion)  such that it is an integral number of `blockSizeinBytes` long.
///
/// - parameter s: the Swift array
/// - parameter blockSizeInBytes: the block size in bytes (cunningly enough!)
/// - returns: a Swift string
///
public func zeroPad(_ s: String, _ blockSize: Int) -> [UInt8] {
    return zeroPad(Array<UInt8>(s.utf8), blockSize)
}
