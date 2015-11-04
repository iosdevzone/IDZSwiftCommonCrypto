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
    // MARK: MD2 (RFC1319)
    let md2inputs = ["", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"]
    let md2outputs = ["8350e5a3e24c153df2275c9f80692773", "32ec01ec4a6dac72c0ab96fb34c0b5d1",
    "da853b0d3f88d99b30283a69e6ded6bb", "ab4f496bfb2a530b219ff33031fe06b0", "4e8ddff3650292ab5a4108c3aa47940b", "da33def2a42df13975352846c30338cd", "d5976f79d83d3a0dc9806c3c66f3efd8"]
    
    func testMD2() {
        for i in 0..<md2inputs.count {
            let input = md2inputs[i]
            let expectedOutput = arrayFromHexString(md2outputs[i])
            let d : Digest = Digest(algorithm:.MD2)
            d.update(input)
            let output = d.final()
            XCTAssertEqual(output, expectedOutput)
        }
    }
    
    // MARK: MD5
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
    
    // See: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
    let shaShortBlock = "abc"
    let sha1ShortBlockOutput = "a9993e364706816aba3e25717850c26c9cd0d89d"
    let sha224BlockOutput = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    let sha256BlockOutput = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    let sha384BlockOutput = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    let sha512BlockOutput = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    func test_Digest_SHA1_String() {
        let digest = Digest(algorithm: .SHA1).update(shaShortBlock)?.final()
        print(hexStringFromArray(digest!))
        XCTAssertEqual(hexStringFromArray(digest!), sha1ShortBlockOutput)
        
    }
    
    func test_Digest_SHA224_String() {
        let digest = Digest(algorithm: .SHA224).update(shaShortBlock)?.final()
        print(hexStringFromArray(digest!))
        XCTAssertEqual(hexStringFromArray(digest!), sha224BlockOutput)
    }
    
    func test_Digest_SHA256_String() {
        let digest = Digest(algorithm: .SHA256).update(shaShortBlock)?.final()
        print(hexStringFromArray(digest!))
        XCTAssertEqual(hexStringFromArray(digest!), sha256BlockOutput)
    }
    
    func test_Digest_SHA384_String() {
        let digest = Digest(algorithm: .SHA384).update(shaShortBlock)?.final()
        print(hexStringFromArray(digest!))
        //XCTAssertEqual(hexStringFromArray(digest!), sha384BlockOutput)
    }
    
    func test_Digest_SHA512_String() {
        let digest = Digest(algorithm: .SHA512).update(shaShortBlock)?.final()
        print(hexStringFromArray(digest!))
        //XCTAssertEqual(hexStringFromArray(digest!), sha512BlockOutput)
    }

    // MARK: - HMAC tests
    let hmacDefaultKeyMD5 = arrayFromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    let hmacDefaultResultMD5 = arrayFromHexString("9294727a3638bb1c13f48ef8158bfc9d")
    
    let hmacDefaultKeySHA1 = arrayFromHexString("0102030405060708090a0b0c0d0e0f10111213141516171819")
    let hmacDefaultResultSHA1 = arrayFromHexString("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
    
    // See: https://www.ietf.org/rfc/rfc2202.txt
    func test_HMAC_MD5()
    {
        let key = self.hmacDefaultKeyMD5
        let data = "Hi There"
        let expected = self.hmacDefaultResultMD5
        
        let hmac = HMAC(algorithm:.MD5, key:key).update(data)?.final()
        
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
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
    // For HMAC-SHA1-{224,256,384,512}
    // See: http://tools.ietf.org/html/rfc4231
    let rfc4231key1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" // should be 20 bytes
    let rfc4231string1 = "Hi There"
    let rfc4231data1 = "4869205468657265"
    let rfc4231SHA224Output1 = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
    let rfc4231SHA256Output1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    let rfc4231SHA384Output1 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
    let rfc4231SHA512Output1 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    
    func test_HMAC_SHA224()
    {
        let key = arrayFromHexString(self.rfc4231key1)
        let data : [UInt8] = arrayFromHexString(rfc4231data1)
        let expected = arrayFromHexString(self.rfc4231SHA224Output1)
        
        let hmac = HMAC(algorithm: HMAC.Algorithm.SHA224, key:key).update(data)?.final()
        
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
    func test_HMAC_SHA256()
    {
        let key = arrayFromHexString(self.rfc4231key1)
        let data : [UInt8] = arrayFromHexString(rfc4231data1)
        let expected = arrayFromHexString(self.rfc4231SHA256Output1)
        
        let hmac = HMAC(algorithm: HMAC.Algorithm.SHA256, key:key).update(data)?.final()
        
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
    func test_HMAC_SHA384()
    {
        let key = arrayFromHexString(self.rfc4231key1)
        let data : [UInt8] = arrayFromHexString(rfc4231data1)
        let expected = arrayFromHexString(self.rfc4231SHA384Output1)
        
        let hmac = HMAC(algorithm: HMAC.Algorithm.SHA384, key:key).update(data)?.final()
        
        XCTAssertEqual(hmac!, expected, "PASS")
    }
    
    func test_HMAC_SHA512()
    {
        let key = arrayFromHexString(self.rfc4231key1)
        let data : [UInt8] = arrayFromHexString(rfc4231data1)
        let expected = arrayFromHexString(self.rfc4231SHA512Output1)
        
        let hmac = HMAC(algorithm: HMAC.Algorithm.SHA512, key:key).update(data)?.final()
        
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
