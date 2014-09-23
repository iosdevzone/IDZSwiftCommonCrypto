//
//  Utilities.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/21/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

func convertHexDigit(c : Character) -> UInt8
{
    switch c {
        case "0": return UInt8(0x0)
        case "1": return UInt8(0x1)
        case "2": return UInt8(0x2)
        case "3": return UInt8(0x3)
        case "4": return UInt8(0x4)
        case "5": return UInt8(0x5)
        case "6": return UInt8(0x6)
        case "7": return UInt8(0x7)
        case "8": return UInt8(0x8)
        case "9": return UInt8(0x9)
        case "A", "a": return UInt8(0xA)
        case "B", "b": return UInt8(0xB)
        case "C", "c": return UInt8(0xC)
        case "D", "d": return UInt8(0xD)
        case "E", "e": return UInt8(0xE)
        case "F", "f": return UInt8(0xF)
    default: fatalError("convertHexDigit: Invalid hex digit")
    }
}

public func arrayFromHexString(s : String) -> [UInt8]
{
    reflect(s)
    var g = s.generate()
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

public func hexStringFromArray(a : [UInt8], uppercase : Bool = false) -> String
{
    return a.map() { String(format:uppercase ? "%02X" : "%02x", $0) }.reduce("", +)
}