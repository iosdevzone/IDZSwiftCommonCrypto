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
    private let padding: Cryptor.Padding
    
    convenience init(_ filePath: URL, password: String) {
        self.init(filePath, password: password, salt: AESEncryptedFile.defaultSalt)
    }
    
    convenience init(_ filePath: URL, password: String, salt: String, padding: Cryptor.Padding = .PKCS7Padding) {
        let key = AESEncryptedFile.deriveKey(password, salt: salt)
        self.init(filePath, key: key, padding: padding)
    }
    
    init(_ filePath: URL, key: Array<UInt8>, padding: Cryptor.Padding) {
        self.filePath = filePath
        self.key = key
        self.padding = padding
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
    
    public func openInputStream() throws -> CipherInputStream {
        guard let innerStream = InputStream(url: self.filePath) else {
            throw Error.createStreamFailure
        }
        
        innerStream.open()
        
        let algorithm = Cryptor.Algorithm.aes;
        
        // slice off the IV from the start of the file
        var iv = [UInt8](repeating: 0, count: algorithm.blockSize())
        let bytesRead = innerStream.read(&iv, maxLength: iv.count)
        
        if bytesRead != iv.count {
            innerStream.close()
            throw Error.headerReadFailure
        }
        
        let cryptor = StreamCryptor(
            operation: .decrypt,
            algorithm: algorithm,
            mode: .CBC,
            padding: .PKCS7Padding,
            key: self.key,
            iv: iv
        )
        
        return CipherInputStream(cryptor, forStream: innerStream)
    }
    
    public func openOutputStream() throws -> CipherOutputStream {
        guard let innerStream = OutputStream(url: self.filePath, append: false) else {
            throw Error.createStreamFailure
        }
        
        let algorithm = Cryptor.Algorithm.aes;
        let iv = try Random.generateBytes(byteCount: algorithm.blockSize())
        
        let cryptor = StreamCryptor(
            operation: .encrypt,
            algorithm: algorithm,
            mode: .CBC,
            padding: .PKCS7Padding,
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
        
        return CipherOutputStream(cryptor, forStream: innerStream)
    }
}
