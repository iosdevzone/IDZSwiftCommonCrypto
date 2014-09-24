//
//  HMAC.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

public class HMAC
{
    public enum Algorithm
    {
        case SHA1, MD5, SHA224, SHA256, SHA384, SHA512
        
        func nativeValue() -> CCHmacAlgorithm {
            switch self {
            case .SHA1:
                return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case .MD5:
                return CCHmacAlgorithm(kCCHmacAlgMD5)
            case .SHA224:
                return CCHmacAlgorithm(kCCHmacAlgSHA224)
            case .SHA256:
                return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case .SHA384:
                return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case .SHA512:
                return CCHmacAlgorithm(kCCHmacAlgSHA512)
                
            }
        }
        
        public func digestLength() -> Int {
            switch self {
            case .SHA1:
                return Int(CC_SHA1_DIGEST_LENGTH)
            case .MD5:
                return Int(CC_MD5_DIGEST_LENGTH)
            case .SHA224:
                return Int(CC_SHA224_DIGEST_LENGTH)
            case .SHA256:
                return Int(CC_SHA256_DIGEST_LENGTH)
            case .SHA384:
                return Int(CC_SHA384_DIGEST_LENGTH)
            case .SHA512:
                return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
    }
    
    typealias Context = UnsafeMutablePointer<CCHmacContext>
    public var status : Status = .Success
    
    let context = Context.alloc(1)
    var algorithm : Algorithm
    
    public init(algorithm : Algorithm, key : [UInt8]) {
        self.algorithm = algorithm
        CCHmacInit(context, algorithm.nativeValue(), key, size_t(key.count))
    }
    
    init(algorithm : Algorithm, key : String)
    {
        self.algorithm = algorithm
        CCHmacInit(context, algorithm.nativeValue(), key, size_t(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
    }
    
    deinit {
        context.dealloc(1)
    }
    
    public func update(buffer : UnsafePointer<Void>, _ byteCount : size_t)
    {
        CCHmacUpdate(context, buffer, byteCount)
    }
    
    public func update(b : [UInt8]) -> HMAC?
    {
        update(b, size_t(b.count))
        return self
    }
    
    public func update(s : String) -> HMAC?
    {
        update(s, size_t(s.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
        return self
    }
    
    public func final() -> [UInt8]
    {
        var hmac = Array<UInt8>(count:algorithm.digestLength(), repeatedValue:0)
        CCHmacFinal(context, &hmac)
        return hmac
    }
}