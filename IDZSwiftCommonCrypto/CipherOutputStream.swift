//
//  CipherOutputStream.swift
//  IDZSwiftCommonCrypto
//
//  Created by Joshua Noel on 11/18/23.
//  Copyright © 2023 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

public class CipherOutputStream : OutputStreamLike {
    private var cryptor: StreamCryptor
    private var stream: OutputStreamLike
    private var innerBuffer = Array<UInt8>(repeating: 0, count: 1024)
    private var _status: CipherStreamStatus = .commonCrypto(.success)
    private var _closed = false
    
    public var status: CipherStreamStatus { self._status }
    public var closed: Bool { self._closed }
    public var hasCipherUpdateFailure: Bool { self.status != .commonCrypto(.success) }
    
    // NOTE: given stream is expected to have already been opened
    init(_ cryptor: StreamCryptor, forStream stream: OutputStreamLike) {
        self.cryptor = cryptor
        self.stream = stream
    }
    
    public func close() {
        if self.closed {
            return
        }
        
        self.tryWriteFinal()
        self.stream.close()
        self._closed = true
    }

    public func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
        if self.closed || self.hasCipherUpdateFailure {
            return 0
        }
        
        if len > self.innerBuffer.capacity {
            self.innerBuffer = Array<UInt8>(repeating: 0, count: len)
        }
        
        var outerBytesWritten = 0
        
        let updateResult = self.cryptor.update(
            bufferIn: buffer,
            byteCountIn: len,
            bufferOut: &self.innerBuffer,
            byteCapacityOut: self.innerBuffer.capacity,
            byteCountOut: &outerBytesWritten
        )
        
        self.updateStatus(.commonCrypto(updateResult))
        
        if self.hasCipherUpdateFailure {
            return 0
        }
        
        let innerBytesWritten = self.stream.write(&self.innerBuffer, maxLength: outerBytesWritten)
        
        if outerBytesWritten != innerBytesWritten {
            self.updateStatus(.transferError)
        }
        
        return innerBytesWritten
    }
    
    private func updateStatus(_ status: CipherStreamStatus) {
        if status != .commonCrypto(.success) {
            print("CipherOutputStream ERROR: \(status)")
        }
        
        _status = status
    }
    
    private func tryWriteFinal() {
        if self.hasCipherUpdateFailure {
            return
        }
        
        var innerBytesWritten = 0
        
        let finalResult = self.cryptor.final(
            bufferOut: &self.innerBuffer,
            byteCapacityOut: self.innerBuffer.capacity,
            byteCountOut: &innerBytesWritten
        )
        
        self.updateStatus(.commonCrypto(finalResult))
        
        if self.hasCipherUpdateFailure {
            return
        }
        
        let outerBytesWritten = self.stream.write(&self.innerBuffer, maxLength: innerBytesWritten)
        
        if outerBytesWritten != innerBytesWritten {
            self.updateStatus(.transferError)
        }
    }
}
