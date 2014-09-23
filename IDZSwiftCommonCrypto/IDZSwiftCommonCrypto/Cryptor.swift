//
//  Cryptor.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto


public class Cryptor
{
    public enum Operation
    {
        case Encrypt, Decrypt
        
        func nativeValue() -> CCOperation {
            switch self {
            case Encrypt : return CCOperation(kCCEncrypt)
            case Decrypt : return CCOperation(kCCDecrypt)
            }
        }
    }
    
    public enum Algorithm
    {
        case AES, DES, TripleDES, CAST, RC2, Blowfish
        
        public func blockSize() -> Int {
            switch self {
            case AES : return kCCBlockSizeAES128
            case DES : return kCCBlockSizeDES
            case TripleDES : return kCCBlockSize3DES
            case CAST : return kCCBlockSizeCAST
            case RC2: return kCCBlockSizeRC2
            case Blowfish : return kCCBlockSizeBlowfish
            }
        }
        
        func nativeValue() -> CCAlgorithm
        {
            switch self {
            case AES : return CCAlgorithm(kCCAlgorithmAES)
            case DES : return CCAlgorithm(kCCAlgorithmDES)
            case TripleDES : return CCAlgorithm(kCCAlgorithm3DES)
            case CAST : return CCAlgorithm(kCCAlgorithmCAST)
            case RC2: return CCAlgorithm(kCCAlgorithmRC2)
            case Blowfish : return CCAlgorithm(kCCAlgorithmBlowfish)
            }
        }
    }
    
    /*
    * It turns out to be rather tedious to reprent ORable
    * bitmask style options in Swift. I would love to
    * to say that I was smart enough to figure out the
    * magic incantions below for myself, but it was, in fact,
    * NSHipster
    * From: http://nshipster.com/rawoptionsettype/
    */
    public struct Options : RawOptionSetType, BooleanType {
        private var value: UInt = 0
        
        init(_ value: UInt) {
            self.value = value
        }
        
        public static func fromMask(raw: UInt) -> Options {
            return self(raw)
        }
        
        public static func fromRaw(raw: UInt) -> Options? {
            return self(raw)
        }
        
        public func toRaw() -> UInt {
            return value
        }
        
        public var boolValue: Bool {
            return value != 0
        }
        
        public static var allZeros: Options {
            return self(0)
        }
        
        public static func convertFromNilLiteral() -> Options {
            return self(0)
        }
        
        public static var None: Options           { return self(0) }
        public static var PKCS7Padding: Options    { return self(UInt(kCCOptionPKCS7Padding)) }
        public static var ECBMode: Options      { return self(UInt(kCCOptionECBMode)) }
    }
    
    public enum Status : CCCryptorStatus
    {
        case Success          = 0,
        ParamError       = -4300,
        BufferTooSmall   = -4301,
        MemoryFailure    = -4302,
        AlignmentError   = -4303,
        DecodeError      = -4304,
        Unimplemented    = -4305,
        Overflow         = -4306,
        RNGFailure       = -4307
        
    }

    //MARK: - High-level interface
    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: [UInt8],
        iv : [UInt8])
    {
        self.init(operation:operation, algorithm:algorithm, options:options, key:key, keyLength:UInt(key.count), iv:iv)
    }
    
    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: String,
        iv : String)
    {
        self.init(operation:operation, algorithm:algorithm, options:options, key:key, keyLength:UInt(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)), iv:iv)
    }
    
    

    
    public func update(dataIn: [UInt8], inout dataOut: [UInt8]) -> (UInt, Status)
    {
        var dataOutAvailable = UInt(dataOut.count)
        var dataOutMoved = UInt(0)
        update(dataIn, dataInLength: UInt(dataIn.count), dataOut: &dataOut, dataOutAvailable: UInt(dataOut.count), dataOutMoved: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    // MARK: - Low-level interface
    public init(operation: Operation, algorithm: Algorithm, options: Options, key: UnsafePointer<Void>,
        keyLength: UInt, iv: UnsafePointer<Void>)
    {
        let rawStatus = CCCryptorCreate(operation.nativeValue(), algorithm.nativeValue(), CCOptions(options.toRaw()), key, keyLength, iv, context)
        if let status = Status.fromRaw(rawStatus)
        {
            self.status = status
        }
        else
        {
            NSLog("FATAL_ERROR: CCCryptorCreate returned unexpected status (\(rawStatus)).")
            fatalError("CCCryptorCreate returned unexpected status.")
        }
    }
    
    public func update(dataIn: UnsafePointer<Void>, dataInLength: UInt, dataOut: UnsafeMutablePointer<Void>,
        dataOutAvailable : UInt, inout dataOutMoved : UInt) -> Status
    {
        if(status == .Success)
        {
            let rawStatus = CCCryptorUpdate(context.memory, dataIn, dataInLength, dataOut, dataOutAvailable, &dataOutMoved)
            if let status = Status.fromRaw(rawStatus)
            {
                self.status =  status
            }
            else
            {
                NSLog("FATAL_ERROR: CCCryptorUpdate returned unexpected status (\(rawStatus)).")
                fatalError("CCCryptorUpdate returned unexpected status.")
            }
        }
        return self.status
    }
    
    public func final(dataOut: UnsafeMutablePointer<Void>,
        dataOutAvailable : UInt, inout dataOutMoved : UInt) -> Status
    {
        if(status == .Success)
        {
            let rawStatus = CCCryptorFinal(context.memory, dataOut, dataOutAvailable, &dataOutMoved)
            if let status = Status.fromRaw(rawStatus)
            {
                self.status =  status
            }
            else
            {
                NSLog("FATAL_ERROR: CCCryptorFinal returned unexpected status (\(rawStatus)).")
                fatalError("CCCryptorUpdate returned unexpected status.")
            }
        }
        return self.status
    }
    
    public func getOutputLength(inputLength : UInt, isFinal : Bool = false) -> UInt
    {
        return CCCryptorGetOutputLength(context.memory, inputLength, isFinal)
    }
    
    deinit
    {
        let rawStatus = CCCryptorRelease(context.memory)
        if let status = Status.fromRaw(rawStatus)
        {
            if(status != .Success)
            {
                NSLog("WARNING: CCCryptoRelease failed with status \(rawStatus).")
            }
        }
        else
        {
            NSLog("FATAL_ERROR: CCCryptorUpdate returned unexpected status (\(rawStatus)).")
            fatalError("CCCryptorUpdate returned unexpected status.")
        }
        context.dealloc(1)
    }
    
    private var context = UnsafeMutablePointer<CCCryptorRef>.alloc(1)
    public var status : Status = .Success
}