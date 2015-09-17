//
//  Utilities.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/21/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

func convertHexDigit(c : UnicodeScalar) -> UInt8
{
    switch c {
        case UnicodeScalar("0")...UnicodeScalar("9"): return UInt8(c.value - UnicodeScalar("0").value)
        case UnicodeScalar("a")...UnicodeScalar("f"): return UInt8(c.value - UnicodeScalar("a").value + 0xa)
        case UnicodeScalar("A")...UnicodeScalar("F"): return UInt8(c.value - UnicodeScalar("A").value + 0xa)
        default: fatalError("convertHexDigit: Invalid hex digit")
    }
}


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

public func dataFromHexString(s : String) -> NSData
{
    let a = arrayFromHexString(s)
    return NSData(bytes:a, length:a.count)
}

public func dataFromByteArray(a : [UInt8]) -> NSData
{
    return NSData(bytes:a, length:a.count)
}

public func hexStringFromArray(a : [UInt8], uppercase : Bool = false) -> String
{
    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", combine: +)
}

public func hexNSStringFromArray(a : [UInt8], uppercase : Bool = false) -> NSString
{
    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", combine: +)
}

public func hexListFromArray(a : [UInt8]) -> String
{
    return a.map() { String(format:"0x%02x, ", $0) }.reduce("", combine: +)    
}