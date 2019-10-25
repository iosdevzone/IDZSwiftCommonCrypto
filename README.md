# IDZSwiftCommonCrypto 
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage) [![Build Status](https://travis-ci.org/iosdevzone/IDZSwiftCommonCrypto.svg?branch=master)](https://travis-ci.org/iosdevzone/IDZSwiftCommonCrypto) [![Coverage Status](https://coveralls.io/repos/iosdevzone/IDZSwiftCommonCrypto/badge.svg?branch=master&service=github)](https://coveralls.io/github/iosdevzone/IDZSwiftCommonCrypto?branch=master)


A Swift wrapper for Apple's `CommonCrypto` library.

IDZSwiftCommonCrypto works with both CocoaPods and Cathage. For more details on how to install it into your projects see [INSTALL.md](INSTALL.md)

**If you are using CococaPods you must use `pod cache clean IDZSwiftCommonCrypto --all` after you upgrade Xcode. This is needed to avoid stale module maps being used from the CocoaPods cache. Removing your Podfile.lock and Pods directory is not sufficient.**

IDZSwiftCommonCrypto provides the following classes:

* `Digest` for calculating message digests,
* `HMAC` for calculating Hash-based Message Authentication Codes,
* `Cryptor` for encrypting and decrypting bounded buffers,
* `StreamCryptor` for encrypting and decrypting streaming information, and
* `PBKDF` for deriving key material from a password or passphrase.

Which Release to Use
--------------------
Which version you use depends on which version of Xcode and Swift you are currently using. Please refer to the list below:

* 0.7.4 -- Xcode 7.3.1, Swift 2.2
* 0.8.0 -- Xcode 7.3.1, Swift 2.2, with additional APIs for `CCMode`
* 0.8.3 -- Xcode 8.0, Swift 2.3
* 0.9.x -- Xcode 8.0, Swift 3.0
* 0.10.x -- Xcode 9.0, Swift 4.0
* 0.11.x -- Xcode 10.0, Swift 4.2
* 0.12.x -- Xcode 10.2, Swift 5.0
* 0.13.x -- Xcode 11.0, Swift 5.1, iOS 13.0

Using `Digest`
--------------

To calculate a message digest you create an instance of `Digest`, call `update` one or more times with the data over which the digest is being calculated and finally call `final` to obtain the digest itself.

The `update` method can take a `String`
```swift
let  s = "The quick brown fox jumps over the lazy dog."
var md5s2 : Digest = Digest(algorithm:.MD5)
md5s2.update(s)
let digests2 = md5s2.final()

// According to Wikipedia this should be
// e4d909c290d0fb1ca068ffaddf22cbd0
hexStringFromArray(digests2)
assert(digests2 == arrayFromHexString("e4d909c290d0fb1ca068ffaddf22cbd0"))
```
or an array of `UInt8` elements:
```swift
let b : [UInt8] = 
[0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,
0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,
0x66,0x6f,0x78,0x2e]
var md5s1 : Digest = Digest(algorithm:.MD5)
md5s1.update(b)
let digests1 = md5s1.final()
```

If you only have a single buffer you can simply write
```swift
  var digests3 = Digest(algorithm: .md5).update(b)?.final() // digest is of type [UInt8]?
```
or 
```swift
  var digests4 = Digest(algorithm: .md5).update(s)?.final() // digest is of type [UInt8]?
```

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

```swift
var keys5 = arrayFrom(hexString: "0102030405060708090a0b0c0d0e0f10111213141516171819")
var datas5 : [UInt8] = Array(count:50, repeatedValue:0xcd)
var expecteds5 = arrayFrom(hexString: "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
var hmacs5 = HMAC(algorithm:.sha1, key:keys5).update(datas5)?.final()

// RFC2202 says this should be 4c9007f4026250c6bc8414f9bf50c86c2d7235da
let expectedRFC2202 = arrayFrom(hexString: "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
assert(hmacs5! == expectedRFC2202)
```
### Supported Algorithms
* `.md5`
* `.sha1`
* `.sha224`
* `.sha256`
* `.sha384`
* `.sha512`

## Using `Cryptor`

```swift
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
```

### Supported Algorithms
* `.AES`
* `.DES` 
* `.TripleDES` 
* `.CAST` 
* `.RC2` 
* `.Blowfish`

## Using `StreamCryptor`

To encrypt a large file or a network stream use `StreamCryptor`. The `StreamCryptor` class does not accumulate the encrypted or decrypted data, instead each call to `update` produces an output buffer. 

The example below shows how to use `StreamCryptor` to encrypt and decrypt an image file.
```swift
func crypt(sc : StreamCryptor,  inputStream: InputStream, outputStream: OutputStream, bufferSize: Int) -> (bytesRead: Int, bytesWritten: Int)
{
    var inputBuffer = Array<UInt8>(repeating:0, count:1024)
    var outputBuffer = Array<UInt8>(repeating:0, count:1024)


    var cryptedBytes : Int = 0
    var totalBytesWritten = 0
    var totalBytesRead = 0
    while inputStream.hasBytesAvailable
    {
        let bytesRead = inputStream.read(&inputBuffer, maxLength: inputBuffer.count)
        totalBytesRead += bytesRead
        let status = sc.update(bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)
        assert(status == Status.success)
        if(cryptedBytes > 0)
        {
            let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
            assert(bytesWritten == Int(cryptedBytes))
            totalBytesWritten += bytesWritten
        }
    }
    let status = sc.final(bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)    
    assert(status == Status.success)
    if(cryptedBytes > 0)
    {
        let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
        assert(bytesWritten == Int(cryptedBytes))
        totalBytesWritten += bytesWritten
    }
    return (totalBytesRead, totalBytesWritten)
}

let imagePath = Bundle.main.path(forResource: "Riscal", ofType:"jpg")!
let tmp = NSTemporaryDirectory() as NSString
let encryptedFilePath = "\(tmp)/Riscal.xjpgx"
var decryptedFilePath = "\(tmp)/RiscalDecrypted.jpg"

// Prepare the input and output streams for the encryption operation
guard let imageInputStream = InputStream(fileAtPath: imagePath) else {
    fatalError("Failed to initialize the image input stream.")
}
imageInputStream.open()
guard let  encryptedFileOutputStream = OutputStream(toFileAtPath: encryptedFilePath, append:false) else
{
    fatalError("Failed to open output stream.")
}
encryptedFileOutputStream.open()

// Generate a new, random initialization vector
let initializationVector = try! Random.generateBytes(byteCount: algorithm.blockSize())

// A common way to communicate the initialization vector is to write it at the beginning of the encrypted data.
let bytesWritten = encryptedFileOutputStream.write(initializationVector, maxLength: initializationVector.count)

// Now write the encrypted data
var sc = StreamCryptor(operation:.encrypt, algorithm:algorithm, options:.PKCS7Padding, key:key, iv:initializationVector)
guard  bytesWritten == initializationVector.count else
{
    fatalError("Failed to write initialization vector to encrypted output file.")
}
let outputResult = crypt(sc: sc, inputStream: imageInputStream, outputStream: encryptedFileOutputStream, bufferSize: 1024)
encryptedFileOutputStream.close()
outputResult

// Uncomment this line to verify that the file is encrypted
//var encryptedImage = NSImage(contentsOfFile:encryptedFile)

// Prepare the input and output streams for the decryption operation
guard let encryptedFileInputStream = InputStream(fileAtPath: encryptedFilePath) else
{
    fatalError("Failed to open the encrypted file for input.")
}
encryptedFileInputStream.open()
guard let decryptedFileOutputStream = OutputStream(toFileAtPath: decryptedFilePath, append:false) else {
    fatalError("Failed to open the file for the decrypted output file.")
}
decryptedFileOutputStream.open()

// Read back the initialization vector.
var readbackInitializationVector = Array<UInt8>(repeating: 0, count: algorithm.blockSize())
let bytesRead = encryptedFileInputStream.read(&readbackInitializationVector, maxLength: readbackInitializationVector.count)

// Uncomment this to verify that we did indeed read back the initialization vector.
//assert(readbackInitializationVector == initializationVector)

// Now use the read back initialization vector (along with the key) to
sc = StreamCryptor(operation:.decrypt, algorithm:algorithm, options:.PKCS7Padding, key:key, iv:readbackInitializationVector)
let inputResult = crypt(sc: sc, inputStream: encryptedFileInputStream, outputStream: decryptedFileOutputStream, bufferSize: 1024)

// Uncomment this to verify that decrypt operation consumed all the encrypted data
// and produced the correct output of plaintext output.
//assert(inputResult.bytesRead == outputResult.bytesWritten && inputResult.bytesWritten == outputResult.bytesRead)

var image = NSImage(named:"Riscal.jpg")
var decryptedImage = NSImage(contentsOfFile:decryptedFilePath)
decryptedImage


```

## Using `PBKDF` 

The `PBKDF` class provides a method of deriving keys from a user password. 
The following example derives a 20-byte key:

```swift
let keys6 = PBKDF.deriveKey("password", salt: "salt", prf: .SHA1, rounds: 1, derivedKeyLength: 20)
// RFC 6070 - Should derive 0c60c80f961f0e71f3a9b524af6012062fe037a6
let expectedRFC6070 = arrayFrom(hexString: "0c60c80f961f0e71f3a9b524af6012062fe037a6")
assert(keys6 == expectedRFC6070)
```
### Supported Pseudo-Random Functions
* `.sha1`
* `.sha224` 
* `.sha256` 
* `.sha384` 
* `.sha512`


