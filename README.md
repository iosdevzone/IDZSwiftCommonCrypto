IDZSwiftCommonCrypto
====================

A wrapper for Apple's Common Crypto library written in Swift. (This is still a work in progress. Use at your own risk!)

Using `Digest`
--------------

To calculate a message digest you create an instance of `Digest`, call `update` one or more times with the data over which the digest is being calculated and finally call `final` to obtain the digest itself.

The `update` method can take an array of `UInt8` elements:
```swift
  let b : [UInt8] = 
    [0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,
     0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,
     0x66,0x6f,0x78,0x2e]
  var md5 : Digest = Digest(algorithm:.MD5)
  md5.update(s)
  let digest = md5.final()
```
or a `String`
```swift
  let  s = "The quick brown fox jumps over the lazy dog."
  var md5 : Digest = Digest(algorithm:.MD5)
  md5.update(s)
  let digest = md5.final()
```

If you only have a single buffer you can simply write
```
  var digest = Digest(algorithm: .MD5).update(b)?.final() // digest is of type [UInt8]?
```
or 
```swift
  var digest = Digest(algorithm: .MD5).update(s)?.final() // digest is of type [UInt8]?
```

Using `HMAC`
------------

Calculating a keyed-Hash Message Authentication Code (HMAC) is very similar to calculating a message digest, except that the initialization routine now takes a key as well as an algorithm parameter.

```swift
  var key = arrayFromHexString("0102030405060708090a0b0c0d0e0f10111213141516171819")
  var data : [UInt8] = Array(count:50, repeatedValue:0xcd)
  var expected = arrayFromHexString("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
  var hmac = HMAC(algorithm:.SHA1, key:key).update(data)?.final()
```

Using `PBKDF` 
-------------

```swift
    // RFC 6070 - Should derive 0c60c80f961f0e71f3a9b524af6012062fe037a6
    let key = PBKDF.deriveKey("password", salt: "salt", prf: .SHA1, rounds: 1, derivedKeyLength: 20)
```
