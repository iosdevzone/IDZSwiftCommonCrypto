import Foundation

let verbose = true

// MARK: - Exception Handling
let handler: @convention(c) (NSException) -> Void = {
    exception in
    print("FATAL EXCEPTION: \(exception)")
    exit(1)
}
NSSetUncaughtExceptionHandler(handler)

// MARK: - Task Utilities
func runShellCommand(command: String) -> String? {
    let args: [String] = command.characters.split { $0 == " " }.map(String.init)
    let other = args[1..<args.count]
    let outputPipe = NSPipe()
    let task = NSTask()
    task.launchPath = args[0]
    task.arguments = other.map { $0 }
    task.standardOutput = outputPipe
    task.launch()
    task.waitUntilExit()
    
    guard task.terminationStatus == 0 else { return nil }

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    return String(data:outputData, encoding: NSUTF8StringEncoding)
}

// MARK: - File System Utilities
func fileExists(filePath: String) -> Bool {
    return NSFileManager.defaultManager().fileExistsAtPath(filePath)
}

func mkdir(path: String) -> Bool {
    do {
        try NSFileManager.defaultManager().createDirectoryAtPath(path, withIntermediateDirectories: true, attributes: nil)
        return true
    }
    catch {
        return false
    }
}

// MARK: - String Utilities
func trim(s: String) -> String {
    return ((s as NSString).stringByTrimmingCharactersInSet(NSCharacterSet.whitespaceAndNewlineCharacterSet()) as String)
}

func trim(s: String?) -> String? {
    return (s == nil) ? nil : (trim(s!) as String)
}

@noreturn func reportError(message: String) {
    print("ERROR: \(message)")
    exit(1)
}

// MARK: GenerateCommonCryptoModule
enum SDK: String {
    case iOS = "iphoneos",
        iOSSimulator = "iphonesimulator",
        watchOS = "watchos",
        watchSimulator = "watchsimulator",
        tvOS = "appletvos",
        tvOSSimulator = "appletvsimulator",
        MacOSX = "macosx"
    static let all = [iOS, iOSSimulator, watchOS, watchSimulator, tvOS, tvOSSimulator, MacOSX]
    
}

guard let sdk = SDK(rawValue: Process.arguments[1])?.rawValue else { reportError("SDK must be one of \(SDK.all.map { $0.rawValue })") }
guard let sdkVersion = trim(runShellCommand("/usr/bin/xcrun --sdk \(sdk) --show-sdk-version")) else {
    reportError("ERROR: Failed to determine SDK version for \(sdk)")
}
guard let sdkPath = trim(runShellCommand("/usr/bin/xcrun --sdk \(sdk) --show-sdk-path")) else {
    reportError("ERROR: Failed to determine SDK path for \(sdk)")
}

if verbose {
    print("SDK: \(sdk)")
    print("SDK Version: \(sdkVersion)")
    print("SDK Path: \(sdkPath)")
}

let moduleDirectory: String
let moduleFileName: String
if Process.arguments.count > 2 {
    moduleDirectory =  "\(Process.arguments[2])/Frameworks/\(sdk)/CommonCrypto.framework"
    moduleFileName = "module.map"
}
else {
    moduleDirectory = "\(sdkPath)/System/Library/Frameworks/CommonCrypto.framework"
    moduleFileName = "module.map"
    
    if fileExists(moduleDirectory) {
        reportError("Module directory already exists at \(moduleDirectory).")
    }
}

if !mkdir(moduleDirectory) {
    reportError("Failed to create module directory \(moduleDirectory)")
}

let headerDir = "\(sdkPath)/usr/include/CommonCrypto/"
let headerFile1 = "\(headerDir)/CommonCrypto.h"
let headerFile2 = "\(headerDir)/CommonRandom.h"

let moduleMapFile =
"module CommonCrypto [system] {\n" +
"  header \"\(headerFile1)\"\n" +
"  header \"\(headerFile2)\"\n" +
"  export *\n" +
"}\n"

let moduleMapPath = "\(moduleDirectory)/\(moduleFileName)"
do {
    try moduleMapFile.writeToFile(moduleMapPath, atomically: true, encoding:NSUTF8StringEncoding)
    print("Successfully created module \(moduleMapPath)")
    exit(0)
}
catch {
    reportError("Failed to write module map file to \(moduleMapPath)")
}

