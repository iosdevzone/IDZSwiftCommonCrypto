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

extension InputStreamLike {
    
    public func readText(buffer: Array<UInt8>?, encoding: String.Encoding = .utf8, bufferLength: Int = 1024) -> String? {
        var buf = buffer ?? Array<UInt8>(repeating: 0, count: bufferLength)
        let readCount = self.read(&buf, maxLength: buf.capacity)
        return readCount > 0 ? String(bytes: buf[0..<readCount], encoding: encoding) : nil
    }
    
    public func readAllText(encoding: String.Encoding = .utf8) -> String {
        let buffer = Array<UInt8>(repeating: 0, count: 1024)
        var result = ""
        
        while let parsed = self.readText(buffer: buffer) {
            result += parsed
        }
        
        return result
    }
    
    @discardableResult
    func pipeTo(_ output: OutputStreamLike) -> Int {
        
        let bufferSize = 8192
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var transferred: Int = 0
        var read: Int = 1
        var written: Int = 0
        
        while read > 0 && self.hasBytesAvailable {
            read = self.read(&buffer, maxLength: bufferSize)
            
            if read <= 0 {
                break
            }
            
            written = output.write(buffer, maxLength: read)
            
            if written != read {
                print("InputStream pipeTo() write mismatch! read \(read) bytes, but wrote \(written)")
                return transferred
            }
            
            transferred += written
        }
        
        return transferred
    }
}

extension OutputStreamLike {
    
    @discardableResult
    public func writeUtf8(_ text: String) -> Int {
        let bytes = Array(text.utf8)
        return self.write(bytes, maxLength: bytes.count)
    }
}

public enum CipherStreamStatus : Error, Equatable {
    case innerTransferError,
    outerTransferError,
    finalTransferError,
    commonCrypto(Status)
}
