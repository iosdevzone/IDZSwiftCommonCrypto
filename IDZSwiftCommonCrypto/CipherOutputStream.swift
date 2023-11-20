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
    private var innerBuffer: Array<UInt8>
    private var _status: CipherStreamStatus = .commonCrypto(.success)
    private var _closed = false
    
    public var status: CipherStreamStatus { self._status }
    public var closed: Bool { self._closed }
    public var hasCipherUpdateFailure: Bool { self.status != .commonCrypto(.success) }
    
    // NOTE: given stream is expected to have already been opened
    public init(_ cryptor: StreamCryptor, forStream stream: OutputStreamLike, initialCapacity: Int? = nil) {
        self.cryptor = cryptor
        self.stream = stream
        let capacity = initialCapacity ?? CIPHER_STREAM_DEFAULT_BLOCK_SIZE
        self.innerBuffer = Array<UInt8>(repeating: 0, count: capacity)
    }
    
    public func close() {
        if self.closed {
            return
        }
        
        self.writeFinal()
        self.stream.close()
        self._closed = true
    }

    @discardableResult
    public func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
        if len <= 0 || self.closed || self.hasCipherUpdateFailure {
            return CIPHER_STREAM_ERROR_RESULT
        }

        if len > self.innerBuffer.count && len < CIPHER_STREAM_MAX_BLOCK_SIZE {
            let newSize = len + (len % CIPHER_STREAM_DEFAULT_BLOCK_SIZE)
            self.innerBuffer = Array<UInt8>(repeating: 0, count: newSize)
        }
        
        var outerByteCount = 0
        
        let updateResult = self.cryptor.update(
            bufferIn: buffer,
            byteCountIn: len,
            bufferOut: &self.innerBuffer,
            byteCapacityOut: self.innerBuffer.count,
            byteCountOut: &outerByteCount
        )
        
        self.updateStatus(.commonCrypto(updateResult))
        
        if self.hasCipherUpdateFailure {
            return CIPHER_STREAM_ERROR_RESULT
        }
    
        if outerByteCount <= 0 {
            return 0
        }

        let innerByteCount = self.stream.write(self.innerBuffer, maxLength: outerByteCount)
        
        if innerByteCount != outerByteCount {
            self.updateStatus(.innerTransferError)
            return CIPHER_STREAM_ERROR_RESULT
        }

        return outerByteCount
    }
    
    private func updateStatus(_ status: CipherStreamStatus) {
        if status != .commonCrypto(.success) {
            print("CipherOutputStream ERROR: \(status)")
        }
        
        _status = status
    }
    
    @discardableResult
    private func writeFinal() -> Int {
        if self.hasCipherUpdateFailure {
            return 0
        }
        
        var innerByteCount = 0
        
        let finalResult = self.cryptor.final(
            bufferOut: &self.innerBuffer,
            byteCapacityOut: self.innerBuffer.count,
            byteCountOut: &innerByteCount
        )
        
        self.updateStatus(.commonCrypto(finalResult))
        
        if self.hasCipherUpdateFailure {
            return CIPHER_STREAM_ERROR_RESULT
        }
        
        let outerByteCount = self.stream.write(&self.innerBuffer, maxLength: innerByteCount)
        
        if outerByteCount != innerByteCount {
            self.updateStatus(.finalTransferError)
            return CIPHER_STREAM_ERROR_RESULT
        }
        
        return outerByteCount
    }
}
