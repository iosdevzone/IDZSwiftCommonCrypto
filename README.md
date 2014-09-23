IDZSwiftCommonCrypto
====================

A wrapper for Apple's Common Crypto library written in Swift. (This is still a work in progress. Use at your own risk!)

Using Digest
------------

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
  var digest = Digest(algorithm: .MD5).update(s)?.final() // type: [UInt8]?
```
or 
```swift
  var digest = Digest(algorithm: .MD5).update(s)?.final() // type: [UInt8]?
```
