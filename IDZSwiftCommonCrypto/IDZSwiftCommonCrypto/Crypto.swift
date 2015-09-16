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

public protocol CryptoDigest {
    func digest(algorithm : Digest.Algorithm) -> Self
}

extension CryptoDigest {
    public var MD2: Self { return self.digest(.MD2) }
    public var MD4: Self { return self.digest(.MD4) }
    public var MD5: Self { return self.digest(.MD5) }
    public var SHA1: Self { return self.digest(.SHA1) }
    public var SHA224: Self { return self.digest(.SHA224) }
    public var SHA256: Self { return self.digest(.SHA256) }
    public var SHA384: Self { return self.digest(.SHA384) }
    public var SHA512: Self { return self.digest(.SHA512) }
}

extension NSData : CryptoDigest {
    public func digest(algorithm : Digest.Algorithm) -> Self {
        // This force unwrap may look scary but for CommonCrypto this cannot fail.
        // The API allows for optionals to support the OpenSSL implementation which can.
        let result = (Digest(algorithm: algorithm).update(self)?.final())!
        let data = self.dynamicType.init(bytes: result, length: result.count)
        return data
    }
}

extension String : CryptoDigest {
    public func digest(algorithm : Digest.Algorithm) -> String {
        // This force unwrap may look scary but for CommonCrypto this cannot fail.
        // The API allows for optionals to support the OpenSSL implementation which can.
        let result = (Digest(algorithm: algorithm).update(self as String)?.final())!
        return hexStringFromArray(result)
        
    }
}
