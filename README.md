# IDZSwiftCommonCrypto [![Build Status](https://travis-ci.org/iosdevzone/IDZSwiftCommonCrypto.svg?branch=Travis2829)](https://travis-ci.org/iosdevzone/IDZSwiftCommonCrypto)


A Swift wrapper for Apple's `CommonCrypto` library.

Using `IDZSwiftCommonCrypto`
----------------------------

Since `CommonCrypto` is not a standalone module, you need to generate a fake module map to convince Xcode into allowing you to `import CommonCrypto`. The `GenerateCommonCryptoModule` script provides two methods for doing this. Which method you choose depends on whether you want to able to use `CommonCrypto` and, by extension, `IDZSwiftCommonCrypto` in playgrounds.

To make `CommonCrypto` available to frameworks and playground use the command:
```bash
    ./GenerateCommonCryptoModule iphonesimulator8.0 
```

This command creates a `CommonCrypto.framework` in the SDK system library directory. You should now be able to use either `CommonCrypto` or `IDZSwiftCommonCrypto` in a playground simply importing them or in your own app project by dragging the `IDZSwiftCommonCrypto.xcodeproj` into your project.

If you do not want to add any files to your SDK you can use the command
```bash
    ./GenerateCommonCryptoModule iphonesimulator8.0 .
```
This method creates a `CommonCrypto` directory within the `IDZSwiftCommonCrypto` source tree, so the SDK directories are not altered, but the module is not available in playgrounds. To use the framework in your own project drag the `IDZSwiftCommonCrypto.xcodeproj` into your project and set the **Module Import Path** to the directory containing the `CommonCrypto` directory created by the script. For more about this, see my blog post [Using CommonCrypto in Swift](http://bit.ly/1xMAGQl) 

```swift
import IDZSwiftCommonCrypto
```
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
  var digests3 = Digest(algorithm: .MD5).update(b)?.final() // digest is of type [UInt8]?
```
or 
```swift
  var digests4 = Digest(algorithm: .MD5).update(s)?.final() // digest is of type [UInt8]?
```

### Supported Algorithms
The `Digest` class supports the following algorithms:

* `.MD2` 
* `.MD4` 
* `.MD5` 
* `.SHA1` 
* `.SHA224` 
* `.SHA256`
* `.SHA384`
* `.SHA512`

Using `HMAC`
------------

Calculating a keyed-Hash Message Authentication Code (HMAC) is very similar to calculating a message digest, except that the initialization routine now takes a key as well as an algorithm parameter.

```swift
var keys5 = arrayFromHexString("0102030405060708090a0b0c0d0e0f10111213141516171819")
var datas5 : [UInt8] = Array(count:50, repeatedValue:0xcd)
var expecteds5 = arrayFromHexString("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
var hmacs5 = HMAC(algorithm:.SHA1, key:keys5).update(datas5)?.final()

// RFC2202 says this should be 4c9007f4026250c6bc8414f9bf50c86c2d7235da
let expectedRFC2202 = arrayFromHexString("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
assert(hmacs5! == expectedRFC2202)
```
### Supported Algorithms
* SHA1
* MD5
* SHA224
* SHA256
* SHA384
* SHA512

## Using `Cryptor`

```swift
var key = arrayFromHexString("2b7e151628aed2a6abf7158809cf4f3c")
var plainText = "The quick brown fox jumps over the lazy dog. The fox has more or less had it at this point."

var cryptor = Cryptor(operation:.Encrypt, algorithm:.AES, options:.PKCS7Padding, key:key, iv:Array<UInt8>())
var cipherText = cryptor.update(plainText)?.final()

cryptor = Cryptor(operation:.Decrypt, algorithm:.AES, options:.PKCS7Padding, key:key, iv:Array<UInt8>())
var decryptedPlainText = cryptor.update(cipherText!)?.final()
var decryptedString = decryptedPlainText!.reduce("") { $0 + String(UnicodeScalar($1)) }
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
func crypt(sc : StreamCryptor,  inputStream: NSInputStream, outputStream: NSOutputStream, bufferSize: Int)
{
    var inputBuffer = Array<UInt8>(count:1024, repeatedValue:0)
    var outputBuffer = Array<UInt8>(count:1024, repeatedValue:0)
    inputStream.open()
    outputStream.open()

    var cryptedBytes : UInt = 0    
    while inputStream.hasBytesAvailable
    {
        let bytesRead = inputStream.read(&inputBuffer, maxLength: inputBuffer.count)
        let status = sc.update(inputBuffer, byteCountIn: UInt(bytesRead), bufferOut: &outputBuffer, byteCapacityOut: UInt(outputBuffer.count), byteCountOut: &cryptedBytes)
        assert(status == Status.Success)
        if(cryptedBytes > 0)
        {
            let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
            assert(bytesWritten == Int(cryptedBytes))
        }
    }
    let status = sc.final(&outputBuffer, byteCapacityOut: UInt(outputBuffer.count), byteCountOut: &cryptedBytes)    
    assert(status == Status.Success)
    if(cryptedBytes > 0)
    {
        let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
        assert(bytesWritten == Int(cryptedBytes))
    }
    inputStream.close()
    outputStream.close()
}

let imagePath = NSBundle.mainBundle().pathForResource("Riscal", ofType:"jpg")!
let tmp = NSTemporaryDirectory()
let encryptedFilePath = tmp.stringByAppendingPathComponent("Riscal.xjpgx")
var decryptedFilePath = tmp.stringByAppendingPathComponent("RiscalDecrypted.jpg")

var imageInputStream = NSInputStream(fileAtPath: imagePath)
var encryptedFileOutputStream = NSOutputStream(toFileAtPath: encryptedFilePath, append:false)
var encryptedFileInputStream = NSInputStream(fileAtPath: encryptedFilePath)
var decryptedFileOutputStream = NSOutputStream(toFileAtPath: decryptedFilePath, append:false)

var sc = StreamCryptor(operation:.Encrypt, algorithm:.AES, options:.PKCS7Padding, key:key, iv:Array<UInt8>())
crypt(sc, imageInputStream, encryptedFileOutputStream, 1024)

// Uncomment this line to verify that the file is encrypted
//var encryptedImage = UIImage(contentsOfFile:encryptedFile)

sc = StreamCryptor(operation:.Decrypt, algorithm:.AES, options:.PKCS7Padding, key:key, iv:Array<UInt8>())
crypt(sc, encryptedFileInputStream, decryptedFileOutputStream, 1024)

var image = UIImage(named:"Riscal.jpg")
var decryptedImage = UIImage(contentsOfFile:decryptedFilePath)
```

## Using `PBKDF` 

The `PBKDF` class provides a method of deriving keys from a user password. 
The following example derives a 20-byte key:

```swift
let keys6 = PBKDF.deriveKey("password", salt: "salt", prf: .SHA1, rounds: 1, derivedKeyLength: 20)
// RFC 6070 - Should derive 0c60c80f961f0e71f3a9b524af6012062fe037a6
let expectedRFC6070 = arrayFromHexString("0c60c80f961f0e71f3a9b524af6012062fe037a6")
assert(keys6 == expectedRFC6070)
```
### Supported Pseudo-Random Functions
* `.SHA1`
* `.SHA224` 
* `.SHA256` 
* `.SHA384` 
* `.SHA512`

