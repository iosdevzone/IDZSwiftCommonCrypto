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
    func test_Cryptor_AES_ECB() {
        var key = arrayFromHexString("2b7e151628aed2a6abf7158809cf4f3c")
        var plainText = arrayFromHexString("6bc1bee22e409f96e93d7e117393172a")
        var cipherText = arrayFromHexString("3ad77bb40d7a3660a89ecaf32466ef97")
        //    public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: [UInt8], iv : [UInt8])
        
        var aesEncrypt = Cryptor(operation:.Encrypt, algorithm:.AES, options:.ECBMode, key:key, iv:Array<UInt8>())
        var dataOut = Array<UInt8>(count:cipherText.count, repeatedValue:UInt8(0))
        let (c, status) = aesEncrypt.update(plainText, dataOut: &dataOut)
        XCTAssert(cipherText.count == Int(c) , "Counts are as expected")
        XCTAssertEqual(dataOut, cipherText, "Obtained expected cipher text")
    }
    // MARK: - Digest tests
    func testMD5_1()
    {
        let  s = "The quick brown fox jumps over the lazy dog."
        let expected : Array<UInt8> = [0xe4,0xd9,0x09,0xc2,
            0x90,0xd0,0xfb,0x1c,
            0xa0,0x68,0xff,0xad,
            0xdf,0x22,0xcb,0xd0]
        var md5 : Digest = Digest(algorithm:.MD5)
        md5.update(s)
        let digest = md5.final()
        XCTAssertEqual(digest, expected, "PASS")
    }
    
    func test_Digest_MD5_Composition()
    {
        let  s = "The quick brown fox jumps over the lazy dog."
        let b : [UInt8] = [0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x20,0x6a,0x75,0x6d,0x70,0x73,0x20,0x6f,0x76,0x65,0x72,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x7a,0x79,0x20,0x64,0x6f,0x67,0x2e]
        let expected : Array<UInt8> = [0xe4,0xd9,0x09,0xc2,
            0x90,0xd0,0xfb,0x1c,
            0xa0,0x68,0xff,0xad,
            0xdf,0x22,0xcb,0xd0]
        var digest = Digest(algorithm: .MD5).update(s)?.final()
        XCTAssertEqual(digest!, expected, "PASS")
        
        let s1 = "The quick brown fox"
        let s2 = " jumps over the lazy dog."
        var d : Digest? = nil
        digest = Digest(algorithm: .MD5).update(s1)?.update(s2)?.final()
        XCTAssertEqual(digest!, expected, "PASS")
        
        digest = Digest(algorithm: .MD5).update(b)?.final()
        XCTAssertEqual(digest!, expected, "PASS")

    }
    // MARK: - HMAC tests
    // See: https://www.ietf.org/rfc/rfc2202.txt
    func test_HMAC_SHA1()
    {
        var key = arrayFromHexString("0102030405060708090a0b0c0d0e0f10111213141516171819")
        var data : [UInt8] = Array(count:50, repeatedValue:0xcd)
        var expected = arrayFromHexString("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
        var hmac = HMAC(algorithm:.SHA1, key:key).update(data)?.final()
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
    
    // MARK: - KeyDerivation tests
    // See: https://www.ietf.org/rfc/rfc6070.txt
    func test_KeyDerivation_deriveKey()
    {        
        let tests = [ ("password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            ("password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            ("password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
            ("password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
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
        var bytes = Random.generateBytes(count)
        XCTAssert(bytes.count == count, "Count has expected value")
    }

    
    // MARK: - Utilities tests
    func test_Utilities_arrayFromHexString_lowerCase()
    {
        var s = "deadface"
        var expected : [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
        var result = arrayFromHexString(s)
        XCTAssertEqual(result, expected, "PASS")
    }
    
    func test_Utilities_arrayFromHexString_upperCase()
    {
        var s = "DEADFACE"
        var expected : [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
        var result = arrayFromHexString(s)
        XCTAssertEqual(result, expected, "PASS")
    }
    
    func testHexStringFromArray()
    {
        var v : [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
        XCTAssertEqual(hexStringFromArray(v), "deadface", "PASS (lowercase)")
        XCTAssertEqual(hexStringFromArray(v, uppercase: true), "DEADFACE", "PASS (lowercase)")
    }

    
    
}
