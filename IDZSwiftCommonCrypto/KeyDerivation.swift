//
//  KeyDerivation.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

public class PBKDF
{
    public enum PseudoRandomAlgorithm
    {
        case SHA1, SHA224, SHA256, SHA384, SHA512
        
        func nativeValue() -> CCPseudoRandomAlgorithm
        {
            switch self {
                case SHA1: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
                case SHA224: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
                case SHA256: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
                case SHA384: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
                case SHA512: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
                
            }
        }
    }
    public class func calibrate(passwordLength: Int, saltLength: Int, algorithm: PseudoRandomAlgorithm, derivedKeyLength: Int, msec : UInt32) -> UInt
    {
        return UInt(CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordLength, saltLength, algorithm.nativeValue(), derivedKeyLength, msec))
    }
    
    public class func deriveKey(password: UnsafePointer<Int8>, passwordLen: Int, salt: UnsafePointer<UInt8>, saltLen: Int, prf: PseudoRandomAlgorithm, rounds: uint, derivedKey: UnsafeMutablePointer<UInt8>, derivedKeyLen: Int)
    {
        let status : Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, passwordLen, salt, saltLen, prf.nativeValue(), rounds, derivedKey, derivedKeyLen)
        if(status != Int32(kCCSuccess))
        {
            NSLog("ERROR: CCKeyDerivationPBDK failed with stats \(status).")
            fatalError("ERROR: CCKeyDerivationPBDK failed.")
        }
    }
    
    public class func deriveKey(password : String, salt : String, prf: PseudoRandomAlgorithm, rounds: uint, derivedKeyLength: UInt) -> [UInt8]
    {
        var derivedKey = Array<UInt8>(count:Int(derivedKeyLength), repeatedValue: 0)
        let status : Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.lengthOfBytesUsingEncoding(NSUTF8StringEncoding), salt, salt.lengthOfBytesUsingEncoding(NSUTF8StringEncoding), prf.nativeValue(), rounds, &derivedKey, derivedKey.count)
        if(status != Int32(kCCSuccess))
        {
            NSLog("ERROR: CCKeyDerivationPBDK failed with stats \(status).")
            fatalError("ERROR: CCKeyDerivationPBDK failed.")
        }
        return derivedKey
    }
}