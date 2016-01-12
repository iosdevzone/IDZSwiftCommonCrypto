//
//  HMAC.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

///
/// Calculates a cryptographic Hash-Based Message Authentication Code (HMAC).
///
public class HMAC : Updateable
{
    ///
    /// Enumerates available algorithms.
    ///
    public enum Algorithm
    {
        /// Message Digest 5
        case MD5,
        /// Secure Hash Algorithm 1
            SHA1,
        /// Secure Hash Algorithm 2 224-bit
            SHA224,
        /// Secure Hash Algorithm 2 256-bit
            SHA256,
        /// Secure Hash Algorithm 2 384-bit
            SHA384,
        /// Secure Hash Algorithm 2 512-bit
            SHA512
        
        static let fromNative : [CCHmacAlgorithm: Algorithm] = [
            CCHmacAlgorithm(kCCHmacAlgSHA1):.SHA1,
            CCHmacAlgorithm(kCCHmacAlgSHA1):.MD5,
            CCHmacAlgorithm(kCCHmacAlgSHA256):.SHA256,
            CCHmacAlgorithm(kCCHmacAlgSHA384):.SHA384,
            CCHmacAlgorithm(kCCHmacAlgSHA512):.SHA512,
            CCHmacAlgorithm(kCCHmacAlgSHA224):.SHA224 ]
        
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
        
        static func fromNativeValue(nativeAlg : CCHmacAlgorithm) -> Algorithm?
        {
            return fromNative[nativeAlg]
        }
        
        ///
        /// Obtains the digest length produced by this algorithm (in bytes).
        ///
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
    
    /// Status of the calculation
    public var status : Status = .Success
    
    let context = Context.alloc(1)
    var algorithm : Algorithm
    
    init(algorithm : Algorithm, keyBuffer: UnsafePointer<Void>, keyByteCount: Int)
    {
        self.algorithm = algorithm
        CCHmacInit(context, algorithm.nativeValue(), keyBuffer, size_t(keyByteCount))
    }
    
    ///
    /// Creates a new HMAC instance with the specified algorithm and key.
    ///
    /// - parameter algorithm: selects the algorithm
    /// - parameter key: specifies the key
    ///
    public init(algorithm : Algorithm, key : NSData)
    {
        self.algorithm = algorithm
        CCHmacInit(context, algorithm.nativeValue(), key.bytes, size_t(key.length))
    }
    
    ///
    /// Creates a new HMAC instance with the specified algorithm and key.
    ///
    /// - parameter algorithm: selects the algorithm
    /// - parameter key: specifies the key
    ///
    public init(algorithm : Algorithm, key : [UInt8])
    {
        self.algorithm = algorithm
        CCHmacInit(context, algorithm.nativeValue(), key, size_t(key.count))
    }
    
    ///
    /// Creates a new HMAC instance with the specified algorithm and key string.
    /// The key string is converted to bytes using UTF8 encoding.
    ///
    /// - parameter algorithm: selects the algorithm
    /// - parameter key: specifies the key
    ///
    public init(algorithm : Algorithm, key : String)
    {
        self.algorithm = algorithm
        CCHmacInit(context, algorithm.nativeValue(), key, size_t(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
    }
    
    deinit {
        context.dealloc(1)
    }
 
    ///
    /// Updates the calculation of the HMAC with the contents of a buffer.
    ///
    /// - returns: the calculated HMAC
    ///
    public func update(buffer : UnsafePointer<Void>, _ byteCount : size_t) -> Self?
    {
        CCHmacUpdate(context, buffer, byteCount)
        return self 
    }
    
    ///
    /// Finalizes the HMAC calculation
    ///
    /// - returns: the calculated HMAC
    ///
    public func final() -> [UInt8]
    {
        var hmac = Array<UInt8>(count:algorithm.digestLength(), repeatedValue:0)
        CCHmacFinal(context, &hmac)
        return hmac
    }
}

