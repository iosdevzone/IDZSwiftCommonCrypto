// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "IDZSwiftCommonCrypto",
    products: [
        .library(
            name: "IDZSwiftCommonCrypto",
            targets: ["IDZSwiftCommonCrypto"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "IDZSwiftCommonCrypto",
            dependencies: []),
        .testTarget(
            name: "IDZSwiftCommonCryptoTests",
            dependencies: ["IDZSwiftCommonCrypto"]),
    ]
)
