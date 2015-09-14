//
//  Cryptor.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/23/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

/**
     Encrypts or decrypts, accumulating result.

     Useful for small in-memory buffers.

     For large files or network streams use StreamCryptor.
 */
public class Cryptor : StreamCryptor
{
    var accumulator : [UInt8] = []
    /**
        Upates the accumulated encrypted/decrypted data with the contents
        of a Objective-C NSData buffer.
        
        - parameter data: the data buffer
        - returns: this Cryptor object or nil if an error occurs (for optional chaining)
    */
    public func update(data: NSData) -> Cryptor?
    {
        update(data.bytes, byteCount: data.length)
        return self.status == Status.Success ? self : nil
    }
    /**
        Upates the accumulated encrypted/decrypted data with the contents
        of a Swift byte array.
        
        - parameter byteArray: the Swift byte array
        - returns: this Cryptor object or nil if an error occurs (for optional chaining)
    */
    public func update(byteArray: [UInt8]) -> Cryptor?
    {
        update(byteArray, byteCount: byteArray.count)
        return self.status == Status.Success ? self : nil
    }
    /**
        Upates the accumulated encrypted/decrypted data with the contents
        of a string (interpreted as UTF8).
        
        This is really only useful for encryption.
        
        - returns: this Cryptor object or nil if an error occurs (for optional chaining)
    */
    public func update(string: String) -> Cryptor?
    {
        update(string, byteCount: string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        return self.status == Status.Success ? self : nil
    }
    /**
        Retrieves the encrypted or decrypted data.
        
        - returns: the encrypted or decrypted data or nil if an error occured.
    */
    public func final() -> [UInt8]?
    {
        let byteCount = Int(self.getOutputLength(0, isFinal: true))
        var dataOut = Array<UInt8>(count:byteCount, repeatedValue:0)
        var dataOutMoved = 0
        (dataOutMoved, self.status) = final(&dataOut)
        if(self.status != Status.Success) {
            return nil
        }
        accumulator += dataOut[0..<Int(dataOutMoved)]
        return accumulator
    }
    
    // MARK: - Low-level interface
    /**
        Upates the accumulated encrypted/decrypted data with the contents
        of a raw byte buffer.
        
        It is not envisaged the users of the framework will need to call this directly.
        
        - returns: this Cryptor object or nil if an error occurs (for optional chaining)
    */
    public func update(buffer: UnsafePointer<Void>, byteCount: Int) -> Cryptor?
    {
        let outputLength = self.getOutputLength(byteCount, isFinal: false)
        var dataOut = Array<UInt8>(count:outputLength, repeatedValue:0)
        var dataOutMoved = 0
        update(buffer, byteCountIn: byteCount, bufferOut: &dataOut, byteCapacityOut: dataOut.count, byteCountOut: &dataOutMoved)
        if(self.status != Status.Success) {
            return nil
        }
        accumulator += dataOut[0..<Int(dataOutMoved)]
        return self
    }
}
