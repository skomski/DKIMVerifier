// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "DKIMVerifier",
  platforms: [
    .macOS(.v10_15), .iOS(.v10),
  ],
  products: [
    .library(
      name: "DKIMVerifier", type: .static,
      targets: ["DKIMVerifier"]),
    .executable(name: "DKIMVerifierTool", targets: ["DKIMVerifierTool"]),
  ],
  dependencies: [
    .package(
      name: "RegularExpressions", url: "https://github.com/Peter-Schorn/RegularExpressions",
      .branch("master")),
    .package(
      name: "swift-argument-parser", url: "https://github.com/apple/swift-argument-parser",
      from: "0.4.0"),
    .package(name: "swift-crypto", url: "https://github.com/apple/swift-crypto", .branch("main")),
  ],
  targets: [
    .target(
      name: "DKIMVerifier",
      dependencies: [
        "RegularExpressions", .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "_CryptoExtras", package: "swift-crypto"),
      ]),
    .target(
      name: "DKIMVerifierTool",
      dependencies: [
        "DKIMVerifier",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
      ]),
    .testTarget(
      name: "DKIMVerifierTests",
      dependencies: ["DKIMVerifier"],
      resources: [
        .process("Resources")
      ]),
  ]
)
