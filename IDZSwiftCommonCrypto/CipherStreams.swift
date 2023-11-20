//
//  CipherStream.swift
//  IDZSwiftCommonCrypto
//
//  Created by Joshua Noel on 11/19/23.
//  Copyright © 2023 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

let CIPHER_STREAM_DEFAULT_BLOCK_SIZE: Int = 1024
let CIPHER_STREAM_MAX_BLOCK_SIZE: Int = CIPHER_STREAM_DEFAULT_BLOCK_SIZE * 16
let CIPHER_STREAM_ERROR_RESULT: Int = -1

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

public extension InputStreamLike {
    
    func readText(buffer: Array<UInt8>?, encoding: String.Encoding = .utf8, bufferLength: Int? = nil) -> String? {
        let len = bufferLength ?? CIPHER_STREAM_DEFAULT_BLOCK_SIZE
        var buf = buffer ?? Array<UInt8>(repeating: 0, count: len)
        let readCount = self.read(&buf, maxLength: buf.count)
        return readCount > 0 ? String(bytes: buf[0..<readCount], encoding: encoding) : nil
    }
    
    func readAllText(encoding: String.Encoding = .utf8) -> String {
        let buffer = Array<UInt8>(repeating: 0, count: CIPHER_STREAM_DEFAULT_BLOCK_SIZE)
        var result = ""
        
        while let parsed = self.readText(buffer: buffer) {
            result += parsed
        }
        
        return result
    }
}

public extension OutputStreamLike {
    
    @discardableResult
    func writeBytes(_ bytes: Array<UInt8>) -> Int {
        return self.write(bytes, maxLength: bytes.count)
    }
    
    @discardableResult
    func writeUtf8(_ text: String) -> Int {
        return self.writeBytes(Array(text.utf8))
    }
}

public enum CipherStreamStatus : Error, Equatable {
    case innerTransferError,
    outerTransferError,
    finalTransferError,
    commonCrypto(Status)
}
