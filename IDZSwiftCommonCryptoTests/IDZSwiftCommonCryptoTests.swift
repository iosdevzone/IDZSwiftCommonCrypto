//
//  IDZSwiftCommonCryptoTests.swift
//  IDZSwiftCommonCryptoTests
//
//  Created by idz on 9/20/14.
//  Copyright (c) 2014 iOSDeveloperZone.com. All rights reserved.
//

import UIKit
import XCTest
import IDZSwiftCommonCrypto

class IDZSwiftCommonCryptoTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    // MARK: - Cryptor tests
    var aesKey1Bytes = arrayFromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    var aesPlaintext1Bytes = arrayFromHexString("6bc1bee22e409f96e93d7e117393172a")
    var aesCipherText1Bytes = arrayFromHexString("3ad77bb40d7a3660a89ecaf32466ef97")
    
    func test_Cryptor_AES_ECB() {
        let aesEncrypt = Cryptor(operation:.Encrypt, algorithm:.AES, options:.ECBMode,
            key:aesKey1Bytes, iv:Array<UInt8>())
        var dataOut = Array<UInt8>(count:aesCipherText1Bytes.count, repeatedValue:UInt8(0))
        let (c, status) = aesEncrypt.update(aesPlaintext1Bytes, byteArrayOut: &dataOut)
        XCTAssert(status == .Success);
        XCTAssert(aesCipherText1Bytes.count == Int(c) , "Counts are as expected")
        XCTAssertEqual(dataOut, aesCipherText1Bytes, "Obtained expected cipher text")
    }
    /**
    Tests two blocks of ECB mode AES. Demonstrates weakness in ECB; repeated plaintext block
    results in repeated ciphertext block.
    */
    func test_Cryptor_AES_ECB_2() {
        let key = aesKey1Bytes
        let plainText = aesPlaintext1Bytes + aesPlaintext1Bytes
        let expectedCipherText = aesCipherText1Bytes + aesCipherText1Bytes
        
        let cipherText = Cryptor(operation:.Encrypt, algorithm:.AES, options:.ECBMode, key:key, iv:Array<UInt8>()).update(plainText)?.final()
        
        assert(expectedCipherText.count == cipherText!.count , "Counts are as expected")
        assert(expectedCipherText == cipherText!, "Obtained expected cipher text")
    }
    /**
    Demonstrates alignment error when plaintext is not an integral number 
    of blocks long.
    */
    func test_Cryptor_AES_ECB_Short() {
        let key = arrayFromHexString("2b7e151628aed2a6abf7158809cf4f3c")
        let plainText = arrayFromHexString("6bc1bee22e409f96e93d7e11739317")        
        let cryptor = Cryptor(operation:.Encrypt, algorithm:.AES, options:.ECBMode, key:key, iv:Array<UInt8>())
        let cipherText = cryptor.update(plainText)?.final()
        XCTAssert(cipherText == nil, "Expected nil cipherText")
        XCTAssertEqual(cryptor.status, Status.AlignmentError, "Expected AlignmentError")
    }
    /**
    Single block CBC mode. Results should be identical to ECB mode.
    */
    func test_Cryptor_AES_CBC_1() {
        let key =   arrayFromHexString("2b7e151628aed2a6abf7158809cf4f3c")
        let iv =    arrayFromHexString("00000000000000000000000000000000")
        let plainText = arrayFromHexString("6bc1bee22e409f96e93d7e117393172a")
        let expectedCipherText = arrayFromHexString("3ad77bb40d7a3660a89ecaf32466ef97")
        
        //var cipherText = Cryptor(operation:.Encrypt, algorithm:.AES, options:.None, key:key, iv:Array<UInt8>()).update(plainText)?.final()
        let cipherText = Cryptor(operation:.Encrypt, algorithm:.AES, options:.None, key:key, iv:iv).update(plainText)?.final()
        
        XCTAssert(expectedCipherText.count == cipherText!.count , "Counts are as expected")
        XCTAssert(expectedCipherText == cipherText!, "Obtained expected cipher text")
        
        print(hexStringFromArray(cipherText!))
        
        let decryptedText = Cryptor(operation:.Decrypt, algorithm:.AES, options:.None, key:key, iv:iv).update(cipherText!)?.final()
        XCTAssertEqual(decryptedText!, plainText, "Recovered plaintext.")
    }
    

    /**
    This is UTF8 encoded "The quick brown fox jumps over the lazy dog."
    */
    let qbfBytes : [UInt8] = [0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x20,0x6a,0x75,0x6d,0x70,0x73,0x20,0x6f,0x76,0x65,0x72,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x7a,0x79,0x20,0x64,0x6f,0x67,0x2e]
    let qbfString = "The quick brown fox jumps over the lazy dog."
    /**
    This is the MD5 for "The quick brown fox jumps over the lazy dog."
    */
    let qbfMD5 : [UInt8] = [0xe4,0xd9,0x09,0xc2,
        0x90,0xd0,0xfb,0x1c,
        0xa0,0x68,0xff,0xad,
        0xdf,0x22,0xcb,0xd0]
    
    // MARK: - Digest tests
    func testMD5_1()
    {
        let md5 : Digest = Digest(algorithm:.MD5)
        md5.update(qbfString)
        let digest = md5.final()
        
        XCTAssertEqual(digest, qbfMD5, "PASS")
    }
    
    func test_Digest_MD5_NSData()
    {
        let qbfData : NSData = dataFromByteArray(self.qbfBytes)
        let digest = Digest(algorithm: .MD5).update(qbfData)?.final()
        
        XCTAssertEqual(digest!, qbfMD5, "PASS")
    }
    /**
    Test MD5 with string input and optional chaining.
    */
    func test_Digest_MD5_Composition_String()
    {
        let digest = Digest(algorithm: .MD5).update(qbfString)?.final()
        XCTAssertEqual(digest!, qbfMD5, "PASS")
    }
    /**
    Test MD5 with optional chaining, string input and 2 updates 
    */
    func test_Digest_MD5_Composition_String_2()
    {
        let s1 = "The quick brown fox"
        let s2 = " jumps over the lazy dog."
        let digest = Digest(algorithm: .MD5).update(s1)?.update(s2)?.final()
        
        XCTAssertEqual(digest!, qbfMD5, "PASS")
    }
    /**
    Test MD5 with optional chaining and byte array input
    */
    func test_Digest_MD5_Composition_Bytes()
    {
        let digest = Digest(algorithm: .MD5).update(qbfBytes)?.final()
        
        XCTAssertEqual(digest!, qbfMD5, "PASS")
    }

    // MARK: - HMAC tests
    let hmacDefaultKeySHA1 = arrayFromHexString("0102030405060708090a0b0c0d0e0f10111213141516171819")
    let hmacDefaultResultSHA1 = arrayFromHexString("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
    
    // See: https://www.ietf.org/rfc/rfc2202.txt
    func test_HMAC_SHA1()
    {
        let key = self.hmacDefaultKeySHA1
        let data : [UInt8] = Array(count:50, repeatedValue:0xcd)
        let expected = self.hmacDefaultResultSHA1
        
        let hmac = HMAC(algorithm:.SHA1, key:key).update(data)?.final()
        
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
    func test_HMAC_SHA1_NSData()
    {
        let key = self.hmacDefaultKeySHA1
        let data = dataFromByteArray(Array<UInt8>(count:50, repeatedValue:0xcd))
        let expected = self.hmacDefaultResultSHA1
        
        let hmac = HMAC(algorithm:.SHA1, key:key).update(data)?.final()
        
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
    
    // MARK: - KeyDerivation tests
    // See: https://www.ietf.org/rfc/rfc6070.txt
    func test_KeyDerivation_deriveKey()
    {        
        let tests = [ ("password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            ("password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            ("password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
//            ("password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
            ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
            ("pass\0word", "sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
        ]
        for (password, salt, rounds, dkLen, expected) in tests
        {
            let key = PBKDF.deriveKey(password, salt: salt, prf: .SHA1, rounds: uint(rounds), derivedKeyLength: UInt(dkLen))
            let keyString = hexStringFromArray(key)
            
            XCTAssertEqual(key, arrayFromHexString(expected), "Obtained correct key (\(keyString) == \(expected)")
        }
        
    }

    // MARK: - Random tests
    func test_Random_generateBytes()
    {
        let count = 256*256
        do {
            let bytes = try Random.generateBytes(count)
            XCTAssert(bytes.count == count, "Count has expected value")
        }
        catch {
            XCTAssert(false, "Should never happen.")
        }
    }

    
    // MARK: - Utilities tests
    func test_Utilities_arrayFromHexString_lowerCase()
    {
        let s = "deadface"
        let expected : [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
        let result = arrayFromHexString(s)
        XCTAssertEqual(result, expected, "PASS")
    }
    
    func test_Utilities_arrayFromHexString_upperCase()
    {
        let s = "DEADFACE"
        let expected : [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
        let result = arrayFromHexString(s)
        XCTAssertEqual(result, expected, "PASS")
    }
    
    func testHexStringFromArray()
    {
        let v : [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
        XCTAssertEqual(hexStringFromArray(v), "deadface", "PASS (lowercase)")
        XCTAssertEqual(hexStringFromArray(v, uppercase: true), "DEADFACE", "PASS (lowercase)")
    }

    
    
}
