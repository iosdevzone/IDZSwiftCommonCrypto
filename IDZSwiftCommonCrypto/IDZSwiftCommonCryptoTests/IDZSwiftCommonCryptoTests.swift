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
    
    func testExample() {
        // This is an example of a functional test case.
        XCTAssert(true, "Pass")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
