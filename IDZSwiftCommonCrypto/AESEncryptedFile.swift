//
//  AESEncryptedFile.swift
//  IDZSwiftCommonCrypto
//
//  Created by Joshua Noel on 11/18/23.
//  Copyright © 2023 iOSDeveloperZone.com. All rights reserved.
//

import Foundation

public class AESEncryptedFile {
    public enum Error : Swift.Error {
        case createStreamFailure, headerWriteFailure, headerReadFailure
    }
    
    private static let defaultSalt = "nevergonnagiveyouup"
    
    private let filePath: URL
    private let key: Array<UInt8>
    // Not currently configurable since anything but PKCS7 will break with misalignment errors
    private let padding: Cryptor.Padding = .PKCS7Padding
    
    public convenience init(_ filePath: URL, password: String) {
        self.init(filePath, password: password, salt: AESEncryptedFile.defaultSalt)
    }
    
    public convenience init(_ filePath: URL, password: String, salt: String) {
        let key = AESEncryptedFile.deriveKey(password, salt: salt)
        self.init(filePath, key: key)
    }
    
    public init(_ filePath: URL, key: Array<UInt8>) {
        self.filePath = filePath
        self.key = key
    }
    
    private static func deriveKey(_ password: String, salt: String) -> Array<UInt8> {
        return PBKDF.deriveKey(
            password: password,
            salt: salt,
            prf: .sha256,
            rounds: 8,
            derivedKeyLength: 16 /* AES-128 */
        )
    }
    
    public func openInputStream(withCapacity: Int? = nil) throws -> CipherInputStream {
        guard let innerStream = InputStream(url: self.filePath) else {
            throw Error.createStreamFailure
        }
        
        innerStream.open()
        
        let algorithm = Cryptor.Algorithm.aes
        let blockSize = algorithm.blockSize()
        
        // slice off the IV from the start of the file
        var iv = [UInt8](repeating: 0, count: blockSize)
        let bytesRead = innerStream.read(&iv, maxLength: iv.count)
        
        if bytesRead != iv.count {
            innerStream.close()
            throw Error.headerReadFailure
        }
        
        let cryptor = StreamCryptor(
            operation: .decrypt,
            algorithm: algorithm,
            mode: .CBC,
            padding: self.padding,
            key: self.key,
            iv: iv
        )
        
        let capacity = withCapacity ?? CIPHER_STREAM_DEFAULT_BLOCK_SIZE
        
        return CipherInputStream(
            cryptor,
            forStream: innerStream,
            initialCapacity: capacity
        )
    }
    
    public func openOutputStream(withCapacity: Int? = nil) throws -> CipherOutputStream {
        guard let innerStream = OutputStream(url: self.filePath, append: false) else {
            throw Error.createStreamFailure
        }
        
        let algorithm = Cryptor.Algorithm.aes
        let blockSize = algorithm.blockSize()
        let iv = try Random.generateBytes(byteCount: blockSize)
        
        let cryptor = StreamCryptor(
            operation: .encrypt,
            algorithm: algorithm,
            mode: .CBC,
            padding: self.padding,
            key: self.key,
            iv: iv
        )
        
        innerStream.open()
        
        // write IV as the header of the file so we can decrypt it later
        let bytesWritten = innerStream.write(iv, maxLength: iv.count)
        
        if bytesWritten != iv.count {
            innerStream.close()
            throw Error.headerWriteFailure
        }
        
        let capacity = withCapacity ?? CIPHER_STREAM_DEFAULT_BLOCK_SIZE
        
        return CipherOutputStream(
            cryptor,
            forStream: innerStream,
            initialCapacity: capacity
        )
    }
}
