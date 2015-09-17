//
//  Updateable.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/16/15.
//  Copyright © 2015 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

public protocol Updateable {
    var status : Status { get }
    func update(buffer : UnsafePointer<Void>, _ byteCount : size_t) -> Self?
}

/**
 Factors out update code from Digest, HMAC and Cryptor
*/
extension Updateable {
    public func update(data: NSData) -> Self?
    {
        update(data.bytes, size_t(data.length))
        return self.status == Status.Success ? self : nil
    }
    
    public func update(byteArray : [UInt8]) -> Self?
    {
        update(byteArray, size_t(byteArray.count))
        return self.status == Status.Success ? self : nil
    }
    
    public func update(string: String) -> Self?
    {
        update(string, size_t(string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
        return self.status == Status.Success ? self : nil
    }
}