//
//  Random.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

public class Random
{
    public class func generateBytes(bytes : UnsafeMutablePointer<Void>, byteCount : UInt )
    {
        CCRandomGenerateBytes(bytes, byteCount)
    }
    
    public class func generateBytes(byteCount : Int ) -> [UInt8]
    {
        if(byteCount <= 0)
        {
            fatalError("generateBytes: byteCount must be positve and non-zero")
        }
        var bytes : [UInt8] = Array(count:byteCount, repeatedValue:UInt8(0))
        CCRandomGenerateBytes(&bytes, UInt(byteCount))
        return bytes
    }
}