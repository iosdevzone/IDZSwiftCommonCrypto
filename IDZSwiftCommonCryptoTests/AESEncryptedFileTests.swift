//
//  AESEncryptedFileTests.swift
//  IDZSwiftCommonCryptoTests (iOS)
//
//  Created by Joshua Noel on 11/19/23.
//  Copyright © 2023 iOSDeveloperZone.com. All rights reserved.
//

import XCTest
@testable import IDZSwiftCommonCrypto

final class AESEncryptedFileTests: XCTestCase {

    func testExample() throws {
        let password = "supersecret"
        let plainTextA = "The quick brown fox"
        let plainTextB = " jumps over the lazy dog. Also this is a thing."
        let plainText = plainTextA + plainTextB
        let cacheDirectory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        let cipherFilePath = cacheDirectory.appendingPathComponent("cipher-test.xlog")
        
        print("test encryption file path = \(cipherFilePath)")
        
        let encryptedFile = AESEncryptedFile(cipherFilePath, password: password)
        let outputStream = try encryptedFile.openOutputStream()
        let utf8ByteCount = plainText.utf8.count
        
        outputStream.writeUtf8(plainTextA)
        outputStream.writeUtf8(plainTextB)
        outputStream.close()
        
        let attr = try FileManager.default.attributesOfItem(atPath: cipherFilePath.path)
        let writtenFileSize = attr[FileAttributeKey.size] as! Int
        
        XCTAssertEqual(outputStream.status, .commonCrypto(.success))
        XCTAssertTrue(writtenFileSize >= utf8ByteCount)
        
        let inputStream = try encryptedFile.openInputStream()
        let readText = inputStream.readAllText()
        
        inputStream.close()
        XCTAssertEqual(inputStream.status, .commonCrypto(.success))
        XCTAssertEqual(readText, plainText)
    }
}
