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
public class Cryptor : StreamCryptor, Updateable
{
    var accumulator : [UInt8] = []
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
    public func update(buffer: UnsafePointer<Void>, _ byteCount: Int) -> Self?
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
