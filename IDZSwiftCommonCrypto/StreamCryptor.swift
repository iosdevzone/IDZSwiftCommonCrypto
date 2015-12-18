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

    - note: The underlying cipher may be a block or a stream cipher.

    Use for large files or network streams.

    For small, in-memory buffers Cryptor may be easier to use.
*/
public class StreamCryptor
{
    ///
    /// Enumerates Cryptor operations
    ///
    public enum Operation
    {
        /// Encrypting
        case Encrypt,
        /// Decrypting
        Decrypt
        
        /// Convert to native `CCOperation`
        func nativeValue() -> CCOperation {
            switch self {
            case Encrypt : return CCOperation(kCCEncrypt)
            case Decrypt : return CCOperation(kCCDecrypt)
            }
        }
    }
    
    public enum ValidKeySize {
        case Fixed(Int)
        case Discrete([Int])
        case Range(Int,Int)
        
        /**
            Determines if a given `keySize` is valid for this algorithm.
        */
        func isValidKeySize(keySize: Int) -> Bool {
            switch self {
            case .Fixed(let fixed): return (fixed == keySize)
            case .Range(let min, let max): return ((keySize >= min) && (keySize <= max))
            case .Discrete(let values): return values.contains(keySize)
            }
        }
        
        /**
            Determines the next valid key size; that is, the first valid key size larger 
            than the given value.
            Will return `nil` if the passed in `keySize` is greater than the max.
        */
        func paddedKeySize(keySize: Int) -> Int? {
            switch self {
            case .Fixed(let fixed):
                return (keySize <= fixed) ? fixed : nil
            case .Range(let min, let max):
                return (keySize > max) ? nil : ((keySize < min) ? min : keySize)
            case .Discrete(let values):
                return values.sort().reduce(nil) { answer, current in
                    return answer ?? ((current >= keySize) ? current : nil)
                }
            }
        }
        
        
    }
    ///
    /// Enumerates available algorithms
    ///
    public enum Algorithm
    {
        /// Advanced Encryption Standard
        case AES,
        /// Data Encryption Standard
        DES,
        /// Triple DES
        TripleDES,
        /// CAST
        CAST,
        /// RC2
        RC2,
        /// Blowfish
        Blowfish
        
        /// Blocksize, in bytes, of algorithm.
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
        /// Native, CommonCrypto constant for algorithm.
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
        
        /// Determines the valid key size for this algorithm
        func validKeySize() -> ValidKeySize {
            switch self {
            case AES : return .Discrete([kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256])
            case DES : return .Fixed(kCCKeySizeDES)
            case TripleDES : return .Fixed(kCCKeySize3DES)
            case CAST : return .Range(kCCKeySizeMinCAST, kCCKeySizeMaxCAST)
            case RC2: return .Range(kCCKeySizeMinRC2, kCCKeySizeMaxRC2)
            case Blowfish : return .Range(kCCKeySizeMinBlowfish, kCCKeySizeMaxBlowfish)
            }
        }
        
        /// Tests if a given keySize is valid for this algorithm
        func isValidKeySize(keySize: Int) -> Bool {
            return self.validKeySize().isValidKeySize(keySize)
        }
        
        /// Calculates the next, if any, valid keySize greater or equal to a given `keySize` for this algorithm
        func paddedKeySize(keySize: Int) -> Int? {
            return self.validKeySize().paddedKeySize(keySize)
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
    ///
    /// Maps CommonCryptoOptions onto a Swift struct.
    ///
    public struct Options : OptionSetType {
        public typealias RawValue = Int
        public let rawValue: RawValue
        
        /// Convert from a native value (i.e. `0`, `kCCOptionPKCS7Padding`, `kCCOptionECBMode`)
        public init(rawValue: RawValue) {
            self.rawValue = rawValue
        }
        
        /// Convert from a native value (i.e. `0`, `kCCOptionPKCS7Padding`, `kCCOptionECBMode`)
        public init(_ rawValue: RawValue) {
            self.init(rawValue: rawValue)
        }
        
        /// No options
        public static let None = Options(rawValue: 0)
        /// Use padding. Needed unless the input is a integral number of blocks long.
        public static var PKCS7Padding =  Options(rawValue:kCCOptionPKCS7Padding)
        /// Electronic Code Book Mode. Don't use this.
        public static var ECBMode = Options(rawValue:kCCOptionECBMode)
    }
    

    
    /**
        The status code resulting from the last method call to this Cryptor.
        Used to get additional information when optional chaining collapes.
    */
    public var status : Status = .Success

    //MARK: - High-level interface
    /**
        Creates a new StreamCryptor
    
        - parameter operation: the operation to perform see Operation (Encrypt, Decrypt)
        - parameter algorithm: the algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
        - parameter key: a byte array containing key data
        - parameter iv: a byte array containing initialization vector
    */
    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: [UInt8],
        iv : [UInt8])
    {
        guard let paddedKeySize = algorithm.paddedKeySize(key.count) else {
            fatalError("FATAL_ERROR: Invalid key size")
        }
        
        self.init(operation:operation, algorithm:algorithm, options:options,
            keyBuffer:zeroPad(key, paddedKeySize), keyByteCount:paddedKeySize, ivBuffer:iv)
    }
    /**
        Creates a new StreamCryptor
        
        - parameter operation: the operation to perform see Operation (Encrypt, Decrypt)
        - parameter algorithm: the algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
        - parameter key: a string containing key data (will be interpreted as UTF8)
        - parameter iv: a string containing initialization vector data (will be interpreted as UTF8)
    */
    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: String,
        iv : String)
    {
        let keySize = key.utf8.count
        guard let paddedKeySize = algorithm.paddedKeySize(keySize) else {
            fatalError("FATAL_ERROR: Invalid key size")
        }
        
        self.init(operation:operation, algorithm:algorithm, options:options,
            keyBuffer:zeroPad(key, paddedKeySize),
            keyByteCount:paddedKeySize, ivBuffer:iv)
    }
    /**
        Add the contents of an Objective-C NSData buffer to the current encryption/decryption operation.
        
        - parameter dataIn: the input data
        - parameter byteArrayOut: output data
        - returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func update(dataIn: NSData, inout byteArrayOut: [UInt8]) -> (Int, Status)
    {
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        update(dataIn.bytes, byteCountIn: dataIn.length, bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    /**
        Add the contents of a Swift byte array to the current encryption/decryption operation.

        - parameter byteArrayIn: the input data
        - parameter byteArrayOut: output data
        - returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func update(byteArrayIn: [UInt8], inout byteArrayOut: [UInt8]) -> (Int, Status)
    {
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        update(byteArrayIn, byteCountIn: byteArrayIn.count, bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    /**
        Add the contents of a string (interpreted as UTF8) to the current encryption/decryption operation.

        - parameter byteArrayIn: the input data
        - parameter byteArrayOut: output data
        - returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func update(stringIn: String, inout byteArrayOut: [UInt8]) -> (Int, Status)
    {
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        update(stringIn, byteCountIn: stringIn.lengthOfBytesUsingEncoding(NSUTF8StringEncoding), bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    /**
        Retrieves all remaining encrypted or decrypted data from this cryptor.

        :note: If the underlying algorithm is an block cipher and the padding option has
        not been specified and the cumulative input to the cryptor has not been an integral
        multiple of the block length this will fail with an alignment error.

        :note: This method updates the status property

        - parameter byteArrayOut: the output bffer        
        - returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func final(inout byteArrayOut: [UInt8]) -> (Int, Status)
    {
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        final(&byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    
    // MARK: - Low-level interface
    /**
        - parameter operation: the operation to perform see Operation (Encrypt, Decrypt)
        - parameter algorithm: the algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
        - parameter keyBuffer: pointer to key buffer
        - parameter keyByteCount: number of bytes in the key
        - parameter ivBuffer: initialization vector buffer
    */
    public init(operation: Operation, algorithm: Algorithm, options: Options, keyBuffer: UnsafePointer<Void>,
        keyByteCount: Int, ivBuffer: UnsafePointer<Void>)
    {
        guard algorithm.isValidKeySize(keyByteCount) else  { fatalError("FATAL_ERROR: Invalid key size.") }

        let rawStatus = CCCryptorCreate(operation.nativeValue(), algorithm.nativeValue(), CCOptions(options.rawValue), keyBuffer, keyByteCount, ivBuffer, context)
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
        - parameter bufferIn: pointer to input buffer
        - parameter inByteCount: number of bytes contained in input buffer 
        - parameter bufferOut: pointer to output buffer
        - parameter outByteCapacity: capacity of the output buffer in bytes
        - parameter outByteCount: on successful completion, the number of bytes written to the output buffer
        - returns: 
    */
    public func update(bufferIn: UnsafePointer<Void>, byteCountIn: Int, bufferOut: UnsafeMutablePointer<Void>, byteCapacityOut : Int, inout byteCountOut : Int) -> Status
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
        
        - parameter bufferOut: pointer to output buffer
        - parameter outByteCapacity: capacity of the output buffer in bytes
        - parameter outByteCount: on successful completion, the number of bytes written to the output buffer
    */
    public func final(bufferOut: UnsafeMutablePointer<Void>, byteCapacityOut : Int, inout byteCountOut : Int) -> Status
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
        
        - parameter inputByteCount: number of bytes that will be input.
        - parameter isFinal: true if buffer to be input will be the last input buffer, false otherwise.
    */
    public func getOutputLength(inputByteCount : Int, isFinal : Bool = false) -> Int
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
