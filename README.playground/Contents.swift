/*: 
 
 # IDZSwiftCommonCrypto
 
 A Swift wrapper for Apple's `CommonCrypto` library.
 
 IDZSwiftCommonCrypto provides the following classes:
 
 * `Digest` for calculating message digests,
 * `HMAC` for calculating Hash-based Message Authentication Codes,
 * `Cryptor` for encrypting and decrypting bounded buffers,
 * `StreamCryptor` for encrypting and decrypting streaming information, and
 * `PBKDF` for deriving key material from a password or passphrase.
 
*/
import Cocoa
import IDZSwiftCommonCrypto
/*: Convert this content to Playground Markup

 Using `Digest`
 --------------
 
 To calculate a message digest you create an instance of `Digest`, call `update` one or more times with the data over which the digest is being calculated and finally call `final` to obtain the digest itself.
 
 The `update` method can take a `String`

*/
let  s = "The quick brown fox jumps over the lazy dog."
var md5s2 : Digest = Digest(algorithm:.md5)
md5s2.update(s)
let digests2 = md5s2.final()

// According to Wikipedia this should be
// e4d909c290d0fb1ca068ffaddf22cbd0
hexString(fromArray: digests2)
assert(digests2 == arrayFrom(hexString: "e4d909c290d0fb1ca068ffaddf22cbd0"))
/*:

or an array of `UInt8` elements:

*/
let b : [UInt8] = 
[0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,
0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,
0x66,0x6f,0x78,0x2e]
var md5s1 : Digest = Digest(algorithm:.md5)
md5s1.update(b)
let digests1 = md5s1.final()
/*: Convert this content to Playground Markup

 If you only have a single buffer you can simply write

*/
var digests3 = Digest(algorithm: .md5).update(b)?.final() // digest is of type [UInt8]?
/*: 

 or

*/
var digests4 = Digest(algorithm: .md5).update(s)?.final() // digest is of type [UInt8]?
/*: 
 
 ### Supported Algorithms
 The `Digest` class supports the following algorithms:
 
 * `.md2`
 * `.md4`
 * `.md5`
 * `.sha1`
 * `.sha224`
 * `.sha256`
 * `.sha384`
 * `.sha512`
 
 Using `HMAC`
 ------------
 
 Calculating a keyed-Hash Message Authentication Code (HMAC) is very similar to calculating a message digest, except that the initialization routine now takes a key as well as an algorithm parameter.

*/
var keys5 = arrayFrom(hexString: "0102030405060708090a0b0c0d0e0f10111213141516171819")
var datas5 : [UInt8] = Array(repeating:0xcd, count:50)
var expecteds5 = arrayFrom(hexString: "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
var hmacs5 = HMAC(algorithm:.sha1, key:keys5).update(datas5)?.final()

// RFC2202 says this should be 4c9007f4026250c6bc8414f9bf50c86c2d7235da
let expectedRFC2202 = arrayFrom(hexString: "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
assert(hmacs5! == expectedRFC2202)
/*: 
 
 ### Supported Algorithms
 * `.md5`
 * `.sha1`
 * `.sha224`
 * `.sha256`
 * `.sha384`
 * `.sha512`
 
 ## Using `Cryptor`

`Cryptor` provides a simple interface similar to `Digest` and `HMAC` that is suitable for encrypting or decrypting small amounts of data.
 
 * Note: If the `key` supplied to `Cryptor` is too short it will be zero-padded to the next valid key length (if one exists) otherwise `fatalError` will be called.
     Except when using Electronic Code Book Mode an initialization vector `iv` must be supplied. It should be the same length as the block size of the algorithm.
 
 
 */
let algorithm = Cryptor.Algorithm.aes
var iv = try! Random.generateBytes(byteCount: algorithm.blockSize())
var key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
var plainText = "The quick brown fox jumps over the lazy dog. The fox has more or less had it at this point."

var cryptor = Cryptor(operation:.encrypt, algorithm:algorithm, options:.PKCS7Padding, key:key, iv:iv)
var cipherText = cryptor.update(plainText)?.final()

cryptor = Cryptor(operation:.decrypt, algorithm:algorithm, options:.PKCS7Padding, key:key, iv:iv)
var decryptedPlainText = cryptor.update(cipherText!)?.final()
var decryptedString = String(bytes: decryptedPlainText!, encoding: .utf8)
decryptedString
assert(decryptedString == plainText)

/*:
 
 ### Supported Algorithms
 * `.aes`
 * `.des`
 * `.tripleDES`
 * `.cast`
 * `.rc2`
 * `.blowfish`
 
 ## Using `StreamCryptor`
 
 To encrypt a large file or a network stream use `StreamCryptor`. The `StreamCryptor` class does not accumulate the encrypted or decrypted data, instead each call to `update` produces an output buffer.
 
 The example below shows how to use `StreamCryptor` to encrypt and decrypt an image file.
*/
func crypt(sc : StreamCryptor,  inputStream: InputStream, outputStream: OutputStream, bufferSize: Int)
{
    var inputBuffer = Array<UInt8>(repeating:0, count:1024)
    var outputBuffer = Array<UInt8>(repeating:0, count:1024)
    inputStream.open()
    outputStream.open()

    var cryptedBytes : Int = 0    
    while inputStream.hasBytesAvailable
    {
        let bytesRead = inputStream.read(&inputBuffer, maxLength: inputBuffer.count)
        let status = sc.update(bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)
        assert(status == Status.success)
        if(cryptedBytes > 0)
        {
            let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
            assert(bytesWritten == Int(cryptedBytes))
        }
    }
    let status = sc.final(bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)    
    assert(status == Status.success)
    if(cryptedBytes > 0)
    {
        let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
        assert(bytesWritten == Int(cryptedBytes))
    }
    inputStream.close()
    outputStream.close()
}

let imagePath = Bundle.main.path(forResource: "Riscal", ofType:"jpg")!
let tmp = NSTemporaryDirectory() as NSString
let encryptedFilePath = "\(tmp)/Riscal.xjpgx"
var decryptedFilePath = "\(tmp)/RiscalDecrypted.jpg"

var imageInputStream = InputStream(fileAtPath: imagePath)
var encryptedFileOutputStream = OutputStream(toFileAtPath: encryptedFilePath, append:false)
var encryptedFileInputStream = InputStream(fileAtPath: encryptedFilePath)
var decryptedFileOutputStream = OutputStream(toFileAtPath: decryptedFilePath, append:false)

// Generate a new, random initialization vector
iv = try! Random.generateBytes(byteCount: algorithm.blockSize())
var sc = StreamCryptor(operation:.encrypt, algorithm:algorithm, options:.PKCS7Padding, key:key, iv:iv)
crypt(sc: sc, inputStream: imageInputStream!, outputStream: encryptedFileOutputStream!, bufferSize: 1024)

// Uncomment this line to verify that the file is encrypted
//var encryptedImage = UIImage(contentsOfFile:encryptedFile)

sc = StreamCryptor(operation:.decrypt, algorithm:algorithm, options:.PKCS7Padding, key:key, iv:iv)
crypt(sc: sc, inputStream: encryptedFileInputStream!, outputStream: decryptedFileOutputStream!, bufferSize: 1024)

var image = NSImage(named:"Riscal.jpg")
var decryptedImage = NSImage(contentsOfFile:decryptedFilePath)
/*: 
 
 ## Using `PBKDF`
 
 The `PBKDF` class provides a method of deriving keys from a user password.
 The following example derives a 20-byte key:

*/
let keys6 = PBKDF.deriveKey(password: "password", salt: arrayFrom(string: "salt"), prf: .sha1, rounds: 1, derivedKeyLength: 20)
// RFC 6070 - Should derive 0c60c80f961f0e71f3a9b524af6012062fe037a6
let expectedRFC6070 = arrayFrom(hexString: "0c60c80f961f0e71f3a9b524af6012062fe037a6")
assert(keys6 == expectedRFC6070)
/*: 
 
 ### Supported Pseudo-Random Functions
 * `.sha1`
 * `.sha224`
 * `.sha256`
 * `.sha384`
 * `.sha512`

*/
