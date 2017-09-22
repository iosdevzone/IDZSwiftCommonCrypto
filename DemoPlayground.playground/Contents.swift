
import Foundation
//
// If you get an error on the line below you need to run:
// sudo xcrun -sdk macosx swift GenerateCommonCryptoModule.swift macosx
//
//import CommonCrypto
import IDZSwiftCommonCrypto


// MARK: - Message Digest Demo
let  s = "The quick brown fox jumps over the lazy dog."
var md5 = Digest(algorithm: .md5)
md5.update(string: s)
var digest = md5.final()
var md5String = hexString(fromArray: digest)

s.MD5

// MARK: - HMAC Demogit s
// Data from RFC 2202
var key = arrayFrom(hexString: "0102030405060708090a0b0c0d0e0f10111213141516171819")
var data : [UInt8] = Array(repeating:0xcd, count:50)
var expected = arrayFrom(hexString: "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
var hmac = HMAC(algorithm:.sha1, key:key).update(byteArray: data)?.final()
var sha1String = hexString(fromArray: hmac!)
sha1String


// MARK: - Key Digest Demo
// Data from RFC 6070


let tests = [ ("password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6")]
for (password, salt, rounds, dkLen, expected) in tests
{
    let key0 = PBKDF.deriveKey(password: password, salt: salt, prf: .sha1, rounds: uint(rounds), derivedKeyLength: UInt(dkLen))
    let keyString0 = hexString(fromArray: key0)
    let key1 = PBKDF.deriveKey(password: password, salt: arrayFrom(string: salt), prf: .sha1, rounds: uint(rounds), derivedKeyLength: UInt(dkLen))
    let keyString1 = hexString(fromArray: key1)
}

// MARK: - Random Demo
var randomBytes = hexString(fromArray: try Random.generateBytes(byteCount: 16))

do {
    try Random.generateBytesThrow(byteCount: 16)
}
catch let e {
    print("generateBytesThrow threw \(e)")
}


do {
    try Random.generateBytesThrow(byteCount: 16)
}
catch {
    print("generateBytesThrow threw an error (expected).")
}


// MARK: - Crypto Demo
// Test data from NIST Special Publication 
// F.1.1 p24
// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
func test_StreamCryptor_AES_ECB() {
    let key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    let plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e117393172a")
    let expectedCipherText = arrayFrom(hexString:"3ad77bb40d7a3660a89ecaf32466ef97")
    
    let aesEncrypt = StreamCryptor(operation:.encrypt, algorithm:.aes, options:.ECBMode, key:key, iv:Array<UInt8>())
    var cipherText : [UInt8] = []
    var dataOut = Array<UInt8>(repeating:UInt8(0), count:plainText.count)
    let (byteCount, status) = aesEncrypt.update(byteArrayIn: plainText, byteArrayOut: &dataOut)
    dataOut
    "\(status)"
    status
    
    cipherText += dataOut[0..<Int(byteCount)]
    //(byteCount, status) = aesEncrypt.final(&dataOut)
    //assert(byteCount == 0, "Final byte count is 0")
    assert(expectedCipherText.count == cipherText.count , "Counts are as expected")
    assert(expectedCipherText == cipherText, "Obtained expected cipher text")
}

test_StreamCryptor_AES_ECB()
// Single block ECB mode
func test_Cryptor_AES_ECB_1() {
    let key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    let plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e117393172a")
    let expectedCipherText = arrayFrom(hexString: "3ad77bb40d7a3660a89ecaf32466ef97")
    
    let cipherText = Cryptor(operation:.encrypt, algorithm:.aes, options:.ECBMode, key:key, iv:Array<UInt8>()).update(byteArray: plainText)?.final()

    assert(expectedCipherText.count == cipherText!.count , "Counts are as expected")
    assert(expectedCipherText == cipherText!, "Obtained expected cipher text")
}

test_Cryptor_AES_ECB_1()

// Double repeated block ECB mode 
// Shows weakness of ECB mode -- same plaintext block gets same ciphertext
func test_Cryptor_AES_ECB_2() {
    let key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    var plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e117393172a")
    var expectedCipherText = arrayFrom(hexString: "3ad77bb40d7a3660a89ecaf32466ef97")
    
    plainText += plainText
    expectedCipherText += expectedCipherText
    
    let cipherText = Cryptor(operation:.encrypt, algorithm:.aes, options:.ECBMode, key:key, iv:Array<UInt8>()).update(byteArray: plainText)?.final()
    
    assert(expectedCipherText.count == cipherText!.count , "Counts are as expected")
    assert(expectedCipherText == cipherText!, "Obtained expected cipher text")
}

test_Cryptor_AES_ECB_2()




// Single block ECB mode
func test_Cryptor_AES_ECB_Short() {
    let key = arrayFrom(hexString:"2b7e151628aed2a6abf7158809cf4f3c")
    let plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e11739317")
    let expectedCipherText = arrayFrom(hexString: "3ad77bb40d7a3660a89ecaf32466ef97")
    
    let cryptor = Cryptor(operation:.encrypt, algorithm:.aes, options:.ECBMode, key:key, iv:Array<UInt8>())
    let cipherText = cryptor.update(byteArray: plainText)?.final()
    if(cipherText == nil)
    {
        print("Encryption failed (as expected) with status \(cryptor.status)")
    }
}

test_Cryptor_AES_ECB_Short()

func test_Cryptor_AES_ECB_Short_Padding() {
    let key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    let plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e11739317")
    let expectedCipherText = arrayFrom(hexString: "21ea2ba3e445a0ef710a7c26618d1975")
    
    let cryptor = Cryptor(operation:.encrypt,
        algorithm:.aes,
        options:[.ECBMode,.PKCS7Padding], key:key, iv:Array<UInt8>())
    let cipherText = cryptor.update(byteArray: plainText)?.final()
    assert(cipherText != nil)
    assert(cipherText! == expectedCipherText)
}

//test_Cryptor_AES_ECB_Short_Padding()


//test_Cryptor_AES_CBC_1()

func test_Cryptor_AES_CBC_2() {
    let key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    var plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e117393172a")
    let expectedCipherText = arrayFrom(hexString: "3ad77bb40d7a3660a89ecaf32466ef97025c61efee87e604cd1b12ce9dde5c51")
    
    plainText += plainText
    
    let optionalCipherText = Cryptor(operation:.encrypt, algorithm:.aes, options:.None, key:key, iv:Array<UInt8>()).update(byteArray: plainText)?.final()
    if let cipherText = optionalCipherText
    {

        
        assert(expectedCipherText.count == cipherText.count , "Counts are as expected")
        assert(expectedCipherText == cipherText, "Obtained expected cipher text")
    }
}







