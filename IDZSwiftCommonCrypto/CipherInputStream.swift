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
    private var innerBuffer: Array<UInt8>
    private var _status: CipherStreamStatus = .commonCrypto(.success)
    private var _closed = false
    
    public var status: CipherStreamStatus { self._status }
    public var closed: Bool { self._closed }
    public var hasCipherUpdateFailure: Bool { self.status != .commonCrypto(.success) }
    public var hasBytesAvailable: Bool { self.stream.hasBytesAvailable }
    
    // NOTE: given stream is expected to have already been opened
    public init(_ cryptor: StreamCryptor, forStream stream: InputStreamLike, initialCapacity: Int? = nil) {
        self.cryptor = cryptor
        self.stream = stream
        let capacity = initialCapacity ?? CIPHER_STREAM_DEFAULT_BLOCK_SIZE
        self.innerBuffer = Array<UInt8>(repeating: 0, count: capacity)
    }
    
    public func close() {
        if self.closed {
            return
        }
        
        self.stream.close()
        self._closed = true
    }

    public func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        if len <= 0 || self.closed || self.hasCipherUpdateFailure {
            return CIPHER_STREAM_ERROR_RESULT
        }
        
        if len > self.innerBuffer.count && len < CIPHER_STREAM_MAX_BLOCK_SIZE {
            let newSize = len + (len % CIPHER_STREAM_DEFAULT_BLOCK_SIZE)
            self.innerBuffer = Array<UInt8>(repeating: 0, count: newSize)
        }
        
        let innerByteCount = self.stream.read(&self.innerBuffer, maxLength: len)
        
        if innerByteCount <= 0 {
            return self.readFinalAndClose(buffer, maxLength: len)
        }
        
        var outerByteCount = 0
        
        let updateResult = self.cryptor.update(
            bufferIn: &self.innerBuffer,
            byteCountIn: innerByteCount,
            bufferOut: buffer,
            byteCapacityOut: len,
            byteCountOut: &outerByteCount
        )
        
        self.updateStatus(.commonCrypto(updateResult))
        
        if self.hasCipherUpdateFailure {
            return CIPHER_STREAM_ERROR_RESULT
        }

        return outerByteCount
    }
    
    private func updateStatus(_ status: CipherStreamStatus) {
        if status != .commonCrypto(.success) {
            print("CipherInputStream ERROR: \(status)")
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
        
        if self.hasCipherUpdateFailure {
            return CIPHER_STREAM_ERROR_RESULT
        }
        
        return outputByteCount
    }
}
