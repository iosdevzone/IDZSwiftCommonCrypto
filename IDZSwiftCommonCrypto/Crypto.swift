//
//  Crypto.swift
//  IDZSwiftCommonCrypto
//
// This implements the API of https://github.com/soffes/Crypto
//
//  Created by idz on 9/16/15.
//  Copyright © 2015 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

///
/// Implements a simplified API for calculating digests over single buffers
///
public protocol CryptoDigest {
    /// Calculates a message digest
    func digest(algorithm : Digest.Algorithm) -> Self
}

extension CryptoDigest {
    /// An MD2 digest of this object
    public var MD2: Self { return self.digest(.MD2) }
    /// An MD4 digest of this object
    public var MD4: Self { return self.digest(.MD4) }
    /// An MD5 digest of this object
    public var MD5: Self { return self.digest(.MD5) }
    /// An SHA1 digest of this object
    public var SHA1: Self { return self.digest(.SHA1) }
    /// An SHA224 digest of this object
    public var SHA224: Self { return self.digest(.SHA224) }
    /// An SHA256 digest of this object
    public var SHA256: Self { return self.digest(.SHA256) }
    /// An SHA384 digest of this object
    public var SHA384: Self { return self.digest(.SHA384) }
    /// An SHA512 digest of this object
    public var SHA512: Self { return self.digest(.SHA512) }
}

extension NSData : CryptoDigest {
    ///
    /// Calculates the Message Digest for this data.
    /// 
    /// - parameter algorithm: the digest algorithm to use
    /// - returns: an `NSData` object containing the message digest
    ///
    public func digest(algorithm : Digest.Algorithm) -> Self {
        // This force unwrap may look scary but for CommonCrypto this cannot fail.
        // The API allows for optionals to support the OpenSSL implementation which can.
        let result = (Digest(algorithm: algorithm).update(self)?.final())!
        let data = self.dynamicType.init(bytes: result, length: result.count)
        return data
    }
}

extension String : CryptoDigest {
    ///
    /// Calculates the Message Digest for this string.
    /// The string is converted to raw data using UTF8.
    ///
    /// - parameter algorithm: the digest algorithm to use
    /// - returns: a hex string of the calculated digest
    ///
    public func digest(algorithm : Digest.Algorithm) -> String {
        // This force unwrap may look scary but for CommonCrypto this cannot fail.
        // The API allows for optionals to support the OpenSSL implementation which can.
        let result = (Digest(algorithm: algorithm).update(self as String)?.final())!
        return hexStringFromArray(result)
        
    }
}
