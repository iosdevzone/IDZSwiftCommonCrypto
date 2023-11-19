//
//  CipherStream.swift
//  IDZSwiftCommonCrypto
//
//  Created by Joshua Noel on 11/19/23.
//  Copyright © 2023 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

public protocol StreamLike {
    func close() -> Void
}

public protocol InputStreamLike : StreamLike {
    var hasBytesAvailable: Bool { get }
    func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int
}

public protocol OutputStreamLike : StreamLike {
    func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int
}

extension Stream : StreamLike {
}

extension InputStream : InputStreamLike {
}

extension OutputStream : OutputStreamLike {
}

public enum CipherStreamStatus : CustomStringConvertible, Error, Equatable {
    
    case transferError,
    commonCrypto(Status)
    
    public var description: String {
        if case .commonCrypto(let status) = self {
            return status.description
        } else if case .transferError = self {
            return "TransferError"
        } else {
            return ""
        }
    }
}
