//
//  Random.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

class Random
{
    class func GenerateBytes(bytes : UnsafeMutablePointer<Void>, byteCount : UInt )
    {
        CCRandomGenerateBytes(bytes, byteCount)
    }
}