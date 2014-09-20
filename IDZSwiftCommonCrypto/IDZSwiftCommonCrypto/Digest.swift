//
//  Digest.swift
//  SwiftCommonCrypto
//
//  Created by idz on 9/19/14.
//  Copyright (c) 2014 iOS Developer Zone. All rights reserved.
//

import Foundation
import CommonCrypto

class DigestEngineCC<C> {
    typealias Context = UnsafeMutablePointer<C>
    typealias Buffer = UnsafePointer<Void>
    typealias Digest = UnsafeMutablePointer<UInt8>
    typealias Initializer = (Context) -> (Int32)
    typealias Updater = (Context, Buffer, CC_LONG) -> (Int32)
    typealias Finalizer = (Digest, Context) -> (Int32)
    
    let context = Context.alloc(1)
    var initializer : Initializer
    var updater : Updater
    var finalizer : Finalizer
    var length : Int32
    
    init(initializer : Initializer, updater : Updater, finalizer : Finalizer, length : Int32)
    {
        self.initializer = initializer
        self.updater = updater
        self.finalizer = finalizer
        self.length = length
        initializer(context)
    }
    
    deinit
    {
        context.dealloc(1)
    }
    
    func update(buffer : [UInt8]) {
        updater(context, buffer, CC_LONG(buffer.count))
    }
    
    func update(s : String)
    {
        updater(context, s, CC_LONG(s.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
    }
    
    func final() -> [UInt8]
    {
        let digestLength = Int(CC_MD5_DIGEST_LENGTH)
        var digest = Array<UInt8>(count:digestLength, repeatedValue: 0)
        finalizer(&digest, context)
        return digest
    }
}

protocol DigestEngine
{
    typealias Buffer = UnsafePointer<Void>
    
    func update(buffer: Buffer, _ byteCount: CC_LONG)
    func final() -> [UInt8]
}

class Digest
{
    enum Algorithm
    {
        case MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    }
}

class MD2Engine<Dummy> : DigestEngineCC<CC_MD2_CTX>
{
    init()
    {
        super.init(initializer:CC_MD2_Init, updater:CC_MD2_Update, finalizer:CC_MD2_Final, length:CC_MD2_DIGEST_LENGTH)
    }
}

typealias MD2 = MD2Engine<Void>

class MD4Engine<Dummy> : DigestEngineCC<CC_MD4_CTX>
{
    init()
    {
        super.init(initializer:CC_MD4_Init, updater:CC_MD4_Update, finalizer:CC_MD4_Final, length:CC_MD4_DIGEST_LENGTH)
    }
}

typealias MD4 = MD4Engine<Void>


class MD5Engine<Dummy> : DigestEngineCC<CC_MD5_CTX>
{
    init()
    {
        super.init(initializer:CC_MD5_Init, updater:CC_MD5_Update, finalizer:CC_MD5_Final, length:CC_MD5_DIGEST_LENGTH)
    }
}

typealias MD5 = MD5Engine<Void>

class SHA1Engine<Dummy> : DigestEngineCC<CC_SHA1_CTX>
{
    init()
    {
        super.init(initializer:CC_SHA1_Init, updater:CC_SHA1_Update, finalizer:CC_SHA1_Final, length:CC_SHA1_DIGEST_LENGTH)
    }
}

typealias SHA1 = SHA1Engine<Void>

class SHA224Engine<Dummy> : DigestEngineCC<CC_SHA1_CTX>
{
    init()
    {
        super.init(initializer:CC_SHA1_Init, updater:CC_SHA1_Update, finalizer:CC_SHA1_Final, length:CC_SHA1_DIGEST_LENGTH)
    }
}

typealias SHA224 = SHA224Engine<Void>

class SHA256Engine<Dummy> : DigestEngineCC<CC_SHA256_CTX>
{
    init()
    {
        super.init(initializer:CC_SHA256_Init, updater:CC_SHA256_Update, finalizer:CC_SHA256_Final, length:CC_SHA256_DIGEST_LENGTH)
    }
}

typealias SHA256 = SHA256Engine<Void>

class SHA384Engine<Dummy> : DigestEngineCC<CC_SHA512_CTX>
{
    init()
    {
        super.init(initializer:CC_SHA384_Init, updater:CC_SHA384_Update, finalizer:CC_SHA384_Final, length:CC_SHA384_DIGEST_LENGTH)
    }
}

typealias SHA384 = SHA384Engine<Void>

class SHA512Engine<Dummy> : DigestEngineCC<CC_SHA512_CTX>
{
    init()
    {
        super.init(initializer:CC_SHA512_Init, updater:CC_SHA512_Update, finalizer:CC_SHA512_Final, length:CC_SHA512_DIGEST_LENGTH)
    }
}

typealias SHA512 = SHA512Engine<Void>



