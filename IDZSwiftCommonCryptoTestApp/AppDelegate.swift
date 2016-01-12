//
//  AppDelegate.swift
//  IDZSwiftCommonCryptoTestApp
//
//  Created by idz on 9/14/15.
//  Copyright © 2015 iOSDeveloperZone.com. All rights reserved.
//

import UIKit
import IDZSwiftCommonCrypto

// MARK: - Crypto Demo
func test_StreamCryptor_AES_ECB() {
    let key = arrayFromHexString("2b7e151628aed2a6abf7158809cf4f3c")
    let plainText = arrayFromHexString("6bc1bee22e409f96e93d7e117393172a")
    let expectedCipherText = arrayFromHexString("3ad77bb40d7a3660a89ecaf32466ef97")
    
    let aesEncrypt = StreamCryptor(operation:.Encrypt, algorithm:.AES, options:.ECBMode, key:key, iv:Array<UInt8>())
    var cipherText : [UInt8] = []
    var dataOut = Array<UInt8>(count:plainText.count, repeatedValue:UInt8(0))
    let (byteCount, status) = aesEncrypt.update(plainText, byteArrayOut: &dataOut)

    
    cipherText += dataOut[0..<Int(byteCount)]
    //(byteCount, status) = aesEncrypt.final(&dataOut)
    //assert(byteCount == 0, "Final byte count is 0")
    assert(expectedCipherText.count == cipherText.count , "Counts are as expected")
    assert(expectedCipherText == cipherText, "Obtained expected cipher text")
    
    // Probing https://github.com/iosdevzone/IDZSwiftCommonCrypto/issues/13
    let hmac = HMAC(algorithm: .SHA256, key: "secret_key").update("content")?.final() ?? []
    print(hexStringFromArray(hmac))
}

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?


    func application(application: UIApplication, didFinishLaunchingWithOptions launchOptions: [NSObject: AnyObject]?) -> Bool {
        // Override point for customization after application launch.
        test_StreamCryptor_AES_ECB()
        
        return true
    }

    func applicationWillResignActive(application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(application: UIApplication) {
        // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
    }

    func applicationWillTerminate(application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
    }


}

