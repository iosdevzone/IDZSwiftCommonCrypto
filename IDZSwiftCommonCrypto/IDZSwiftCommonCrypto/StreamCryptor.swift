//
//  Cryptor.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

/**
    Encrypts or decrypts return results as they become available.

    :note: The underlying cipher may be a block or a stream cipher.

    Use for large files or network streams.

    For small, in-memory buffers Cryptor may be easier to use.
*/
public class StreamCryptor
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
    
    /**
        The status code resulting from the last method call to this Cryptor. 
        Used to get additional information when optional chaining collapes.
    */
    public var status : Status = .Success

    //MARK: - High-level interface
    /**
        Creates a new StreamCryptor
    
        :param: operation the operation to perform see Operation (Encrypt, Decrypt)
        :param: algorithm the algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
        :param: key a byte array containing key data
        :param: iv a byte array containing initialization vector
    */
    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: [UInt8],
        iv : [UInt8])
    {
        self.init(operation:operation, algorithm:algorithm, options:options, keyBuffer:key, keyByteCount:UInt(key.count), ivBuffer:iv)
    }
    /**
        Creates a new StreamCryptor
        
        :param: operation the operation to perform see Operation (Encrypt, Decrypt)
        :param: algorithm the algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
        :param: key a string containing key data (will be interpreted as UTF8)
        :param: iv a string containing initialization vector data (will be interpreted as UTF8)
    */
    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: String,
        iv : String)
    {
        self.init(operation:operation, algorithm:algorithm, options:options, keyBuffer:key, keyByteCount:UInt(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)), ivBuffer:iv)
    }
    /**
        Add the contents of an Objective-C NSData buffer to the current encryption/decryption operation.
        
        :param: dataIn the input data
        :param: byteArrayOut output data
        :returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func update(dataIn: NSData, inout byteArrayOut: [UInt8]) -> (UInt, Status)
    {
        var dataOutAvailable = UInt(byteArrayOut.count)
        var dataOutMoved = UInt(0)
        update(dataIn.bytes, byteCountIn: UInt(dataIn.length), bufferOut: &byteArrayOut, byteCapacityOut: UInt(byteArrayOut.count), byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    /**
        Add the contents of a Swift byte array to the current encryption/decryption operation.

        :param: byteArrayIn the input data
        :param: byteArrayOut output data
        :returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func update(byteArrayIn: [UInt8], inout byteArrayOut: [UInt8]) -> (UInt, Status)
    {
        var dataOutAvailable = UInt(byteArrayOut.count)
        var dataOutMoved = UInt(0)
        update(byteArrayIn, byteCountIn: UInt(byteArrayIn.count), bufferOut: &byteArrayOut, byteCapacityOut: UInt(byteArrayOut.count), byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    /**
        Add the contents of a string (interpreted as UTF8) to the current encryption/decryption operation.

        :param: byteArrayIn the input data
        :param: byteArrayOut output data
        :returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func update(stringIn: String, inout byteArrayOut: [UInt8]) -> (UInt, Status)
    {
        var dataOutAvailable = UInt(byteArrayOut.count)
        var dataOutMoved = UInt(0)
        update(stringIn, byteCountIn: UInt(stringIn.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)), bufferOut: &byteArrayOut, byteCapacityOut: UInt(byteArrayOut.count), byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    /**
        Retrieves all remaining encrypted or decrypted data from this cryptor.

        :note: If the underlying algorithm is an block cipher and the padding option has
        not been specified and the cumulative input to the cryptor has not been an integral
        multiple of the block length this will fail with an alignment error.

        :note: This method updates the status property

        :param: byteArrayOut the output bffer        
        :returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func final(inout byteArrayOut: [UInt8]) -> (UInt, Status)
    {
        var dataOutAvailable = UInt(byteArrayOut.count)
        var dataOutMoved = UInt(0)
        final(&byteArrayOut, byteCapacityOut: UInt(byteArrayOut.count), byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    
    // MARK: - Low-level interface
    /**
        :param: operation the operation to perform see Operation (Encrypt, Decrypt)
        :param: algorithm the algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
        :param: keyBuffer pointer to key buffer
        :param: keyByteCount number of bytes in the key
        :param: ivBuffer initialization vector buffer
    */
    public init(operation: Operation, algorithm: Algorithm, options: Options, keyBuffer: UnsafePointer<Void>,
        keyByteCount: UInt, ivBuffer: UnsafePointer<Void>)
    {
        let rawStatus = CCCryptorCreate(operation.nativeValue(), algorithm.nativeValue(), CCOptions(options.toRaw()), keyBuffer, keyByteCount, ivBuffer, context)
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
    /**
        :param: bufferIn pointer to input buffer
        :param: inByteCount number of bytes contained in input buffer 
        :param: bufferOut pointer to output buffer
        :param: outByteCapacity capacity of the output buffer in bytes
        :param: outByteCount on successful completion, the number of bytes written to the output buffer
        :returns: 
    */
    public func update(bufferIn: UnsafePointer<Void>, byteCountIn: UInt, bufferOut: UnsafeMutablePointer<Void>, byteCapacityOut : UInt, inout byteCountOut : UInt) -> Status
    {
        if(self.status == Status.Success)
        {
            let rawStatus = CCCryptorUpdate(context.memory, bufferIn, byteCountIn, bufferOut, byteCapacityOut, &byteCountOut)
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
    /**
        Retrieves all remaining encrypted or decrypted data from this cryptor.
        
        :note: If the underlying algorithm is an block cipher and the padding option has
        not been specified and the cumulative input to the cryptor has not been an integral 
        multiple of the block length this will fail with an alignment error.
    
        :note: This method updates the status property
        
        :param: bufferOut pointer to output buffer
        :param: outByteCapacity capacity of the output buffer in bytes
        :param: outByteCount on successful completion, the number of bytes written to the output buffer
    */
    public func final(bufferOut: UnsafeMutablePointer<Void>, byteCapacityOut : UInt, inout byteCountOut : UInt) -> Status
    {
        if(self.status == Status.Success)
        {
            let rawStatus = CCCryptorFinal(context.memory, bufferOut, byteCapacityOut, &byteCountOut)
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
    /**
        Determines the number of bytes that wil be output by this Cryptor if inputBytes of additional
        data is input.
        
        :param: inputByteCount number of bytes that will be input.
        :param: isFinal true if buffer to be input will be the last input buffer, false otherwise.
    */
    public func getOutputLength(inputByteCount : UInt, isFinal : Bool = false) -> UInt
    {
        return CCCryptorGetOutputLength(context.memory, inputByteCount, isFinal)
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
    
}