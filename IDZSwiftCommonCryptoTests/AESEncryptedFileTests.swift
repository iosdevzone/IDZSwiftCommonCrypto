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

    func test_AESEncryptedFile_canReadBackTheFileItCreates() throws {
        let password = "supersecret"
        let plainTextA = "The quick brown fox"
        let plainTextB = " jumps over the lazy dog. Also this is a thing."
        let plainText = plainTextA + plainTextB
        let cacheDirectory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        let cipherFilePath = cacheDirectory.appendingPathComponent("cipher-test.xlog")
        
        print("test encryption file path = \(cipherFilePath)")
        
        let encryptedFile = AESEncryptedFile(cipherFilePath, password: password)
        let blockSize = Cryptor.Algorithm.aes.blockSize()
        let outputStream = try encryptedFile.openOutputStream()
        let plainTextBytes = Array(plainText.utf8)
        let expectedEncryptedSize = plainTextBytes.count + blockSize
        
        outputStream.writeUtf8(plainTextA)
        outputStream.writeUtf8(plainTextB)
        outputStream.close()

        let writtenData = NSData(contentsOfFile: cipherFilePath.path)!
        var writtenDataBytes = Array<UInt8>(repeating: 0, count: writtenData.length)
        
        writtenData.getBytes(&writtenDataBytes, length: writtenData.length)
        XCTAssertEqual(outputStream.status, .commonCrypto(.success))
        XCTAssertTrue(writtenDataBytes.count >= expectedEncryptedSize)
        XCTAssertNotEqual(writtenDataBytes, plainTextBytes)
        
        let inputStream = try encryptedFile.openInputStream()
        let readText = inputStream.readAllText()
        
        inputStream.close()
        XCTAssertEqual(inputStream.status, .commonCrypto(.success))
        XCTAssertEqual(readText, plainText)
    }
}
