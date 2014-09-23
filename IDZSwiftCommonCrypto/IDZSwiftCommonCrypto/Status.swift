//
//  Status.swift
//  IDZSwiftCommonCrypto
//
//  Created by idz on 9/23/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import Foundation
import CommonCrypto

public enum Status : CCCryptorStatus
{
    case Success,
    ParamError,
    BufferTooSmall,
    MemoryFailure,
    AlignmentError,
    DecodeError,
    Unimplemented,
    Overflow,
    RNGFailure
    
    public func toRaw() -> CCCryptorStatus
    {
        switch self {
        case Success:          return CCCryptorStatus(kCCSuccess)
        case ParamError:       return CCCryptorStatus(kCCParamError)
        case BufferTooSmall:   return CCCryptorStatus(kCCBufferTooSmall)
        case MemoryFailure:    return CCCryptorStatus(kCCMemoryFailure)
        case AlignmentError:   return CCCryptorStatus(kCCAlignmentError)
        case DecodeError:      return CCCryptorStatus(kCCDecodeError)
        case Unimplemented:    return CCCryptorStatus(kCCUnimplemented)
        case Overflow:         return CCCryptorStatus(kCCOverflow)
        case RNGFailure:       return CCCryptorStatus(kCCRNGFailure)
        }
    }
    
    static let descriptions = [ Success: "Success",                 ParamError: "ParamError",
                            BufferTooSmall: "BufferTooSmall",   MemoryFailure: "MemoryFailure",
                            AlignmentError: "AlignmentError",   DecodeError: "DecodeError",
                            Unimplemented: "Unimplemented",     Overflow: "Overflow",
                            RNGFailure: "RNGFailure"]
    public func description() -> String
    {
        return (Status.descriptions[self] != nil) ? Status.descriptions[self]! : ""
    }
    
    public static func fromRaw(status : CCCryptorStatus) -> Status?
    {
        var from = [ kCCSuccess: Success, kCCParamError: ParamError,
            kCCBufferTooSmall: BufferTooSmall, kCCMemoryFailure: MemoryFailure,
            kCCAlignmentError: AlignmentError, kCCDecodeError: DecodeError, kCCUnimplemented: Unimplemented,
            kCCOverflow: Overflow, kCCRNGFailure: RNGFailure]
        return from[Int(status)]
        

//        switch status {
//        case kCCSuccess:          return Success
//        case kCCParamError:       return ParamError
//        case kCCBufferTooSmall:   return BufferTooSmall
//        case kCCMemoryFailure:    return MemoryFailure
//        case kCCAlignmentError:   return AlignmentError
//        case kCCDecodeError:      return DecodeError
//        case kCCUnimplemented:    return Unimplemented
//        case kCCOverflow:         return Overflow
//        case kCCRNGFailure:       return RNGFailure
//        }
    }
}
