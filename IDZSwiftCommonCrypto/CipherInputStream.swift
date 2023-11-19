//
//  CipherInputStream.swift
//  IDZSwiftCommonCrypto
//
//  Created by Joshua Noel on 11/18/23.
//  Copyright © 2023 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

public class CipherInputStream : InputStreamLike {    
    private var cryptor: StreamCryptor
    private var stream: InputStreamLike
    private var innerBuffer = Array<UInt8>(repeating: 0, count: 1024)
    private var _status: CipherStreamStatus = .commonCrypto(.success)
    private var _closed = false
    
    public var status: CipherStreamStatus { self._status }
    public var closed: Bool { self._closed }
    public var hasCipherUpdateFailure: Bool { self.status != .commonCrypto(.success) }
    public var hasBytesAvailable: Bool { self.stream.hasBytesAvailable }
    
    // NOTE: given stream is expected to have already been opened
    init(_ cryptor: StreamCryptor, forStream stream: InputStreamLike) {
        self.cryptor = cryptor
        self.stream = stream
    }
    
    public func close() {
        if self.closed {
            return
        }
        
        self.stream.close()
        self._closed = true
    }

    public func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        if self.closed || self.hasCipherUpdateFailure {
            return 0
        }
        
        if !self.hasBytesAvailable {
            return self.readFinalAndClose(buffer, maxLength: len)
        }
        
        if len > self.innerBuffer.capacity {
            self.innerBuffer = Array<UInt8>(repeating: 0, count: len)
        }
        
        let innerReadCount = self.stream.read(&self.innerBuffer, maxLength: len)
        
        if innerReadCount <= 0 {
            return self.readFinalAndClose(buffer, maxLength: len)
        }
        
        var outerReadCount = 0
        
        let updateResult = self.cryptor.update(
            bufferIn: &self.innerBuffer,
            byteCountIn: innerReadCount,
            bufferOut: buffer,
            byteCapacityOut: len,
            byteCountOut: &outerReadCount
        )
        
        self.updateStatus(.commonCrypto(updateResult))
        
        return outerReadCount
    }
    
    private func updateStatus(_ status: CipherStreamStatus) {
        if status != .commonCrypto(.success) {
            print("CipherOutputStream ERROR: \(status)")
        }
        
        _status = status
    }
    
    private func readFinalAndClose(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        
        var outputByteCount = 0
        
        let finalResult = self.cryptor.final(
            bufferOut: buffer,
            byteCapacityOut: len,
            byteCountOut: &outputByteCount
        )
        
        self.updateStatus(.commonCrypto(finalResult))
        self.close()
        
        return outputByteCount
    }
}
