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
func convertHexDigit(c : UnicodeScalar) -> UInt8
{
    switch c {
        case UnicodeScalar("0")...UnicodeScalar("9"): return UInt8(c.value - UnicodeScalar("0").value)
        case UnicodeScalar("a")...UnicodeScalar("f"): return UInt8(c.value - UnicodeScalar("a").value + 0xa)
        case UnicodeScalar("A")...UnicodeScalar("F"): return UInt8(c.value - UnicodeScalar("A").value + 0xa)
        default: fatalError("convertHexDigit: Invalid hex digit")
    }
}

///
/// Converts a string of hexadecimal digits to a Swift array.
///
/// - parameter s: the hex string (must contain an even number of digits)
/// - returns: a Swift array
///
public func arrayFromHexString(s : String) -> [UInt8]
{
    var g = s.unicodeScalars.generate()
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
public func arrayFromString(s : String) -> [UInt8]
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
public func dataFromHexString(s : String) -> NSData
{
    let a = arrayFromHexString(s)
    return NSData(bytes:a, length:a.count)
}

///
/// Converts a Swift array to an `NSData` object.
///
/// - parameter a: the Swift array
/// - returns: an NSData object
///
public func dataFromByteArray(a : [UInt8]) -> NSData
{
    return NSData(bytes:a, length:a.count)
}

///
/// Converts a Swift array to a string of hexadecimal digits.
///
/// - parameter a: the Swift array
/// - parameter uppercase: if true use uppercase for letter digits, lowercase otherwise
/// - returns: a Swift string
///
public func hexStringFromArray(a : [UInt8], uppercase : Bool = false) -> String
{
    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", combine: +)
}

///
/// Converts a Swift array to an `NSString` object.
///
/// - parameter a: the Swift array
/// - parameter uppercase: if true use uppercase for letter digits, lowercase otherwise
/// - returns: an `NSString` object
///
public func hexNSStringFromArray(a : [UInt8], uppercase : Bool = false) -> NSString
{
    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", combine: +)
}

///
/// Converts a Swift array to a Swift `String` containing a comma separated list of bytes.
/// This is used to generate test data programmatically.
///
/// - parameter a: the Swift array
/// - returns: a Swift string
///
public func hexListFromArray(a : [UInt8]) -> String
{
    return a.map() { String(format:"0x%02x, ", $0) }.reduce("", combine: +)    
}

///
/// Zero pads a Swift array such that it is an integral number of `blockSizeinBytes` long.
///
/// - parameter a: the Swift array
/// - parameter blockSizeInBytes: the block size in bytes (cunningly enough!)
/// - returns: a Swift string
///
public func zeroPad(a: [UInt8], _ blockSize: Int) -> [UInt8] {
    let pad = blockSize - (a.count % blockSize)
    guard pad != 0 else { return a }
    return a + Array<UInt8>(count: pad, repeatedValue: 0)
}

///
/// Zero pads a Swift string (after UTF8 conversion)  such that it is an integral number of `blockSizeinBytes` long.
///
/// - parameter s: the Swift array
/// - parameter blockSizeInBytes: the block size in bytes (cunningly enough!)
/// - returns: a Swift string
///
public func zeroPad(s: String, _ blockSize: Int) -> [UInt8] {
    return zeroPad(Array<UInt8>(s.utf8), blockSize)
}
