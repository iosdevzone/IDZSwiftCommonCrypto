//
//  Cryptor.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/23/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

public class Cryptor : StreamCryptor
{
    var accumulator : [UInt8] = []
    // MARK: - Low-level interface
    public override init(operation: Operation, algorithm: Algorithm, options: Options, key: UnsafePointer<Void>,
        keyLength: UInt, iv: UnsafePointer<Void>)
    {
        super.init(operation: operation, algorithm: algorithm, options: options, key: key, keyLength: keyLength, iv: iv)
    }
    
    public func update(dataIn: [UInt8]) -> Cryptor?
    {
        var byteCount = Int(self.getOutputLength(UInt(dataIn.count), isFinal: false))
        var dataOut = Array<UInt8>(count:byteCount, repeatedValue:0)
        var dataOutAvailable = UInt(dataOut.count)
        var dataOutMoved = UInt(0)
        (dataOutMoved, self.status) = update(dataIn, dataOut: &dataOut)
        if(self.status != Status.Success) {
            return nil
        }
        accumulator += dataOut[0..<Int(dataOutMoved)]
        return self
    }
    
    public func final() -> [UInt8]?
    {
        var byteCount = Int(self.getOutputLength(0, isFinal: true))
        var dataOut = Array<UInt8>(count:byteCount, repeatedValue:0)
        var dataOutAvailable = UInt(dataOut.count)
        var dataOutMoved = UInt(0)
        (dataOutMoved, self.status) = final(&dataOut)
        if(self.status != Status.Success) {
            return nil
        }
        accumulator += dataOut[0..<Int(dataOutMoved)]
        return accumulator
    }
}
