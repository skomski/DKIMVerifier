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
    .library(name: "DKIMVerifierToolBase", targets: ["DKIMVerifierToolBase"]),
    .executable(name: "DKIMVerifierTool", targets: ["DKIMVerifierTool"]),
    .executable(name: "DKIMVerifierTool_unbound", targets: ["DKIMVerifierTool_unbound"]),
    .executable(name: "DKIMVerifierTool_dnssd", targets: ["DKIMVerifierTool_dnssd"]),
  ],
  dependencies: [
    .package(
      name: "RegularExpressions", url: "https://github.com/Peter-Schorn/RegularExpressions",
      .branch("master")),
    .package(
      name: "swift-argument-parser", url: "https://github.com/apple/swift-argument-parser",
      from: "0.4.0"),
    .package(name: "swift-crypto", url: "https://github.com/apple/swift-crypto", .branch("main")),
    .package(
      name: "SwiftParsec", url: "https://github.com/davedufresne/SwiftParsec", .branch("master")),
    .package(name: "Peppermint", url: "https://github.com/nsagora/peppermint", from: "1.1.0"),
  ],
  targets: [
    .systemLibrary(
        name: "libunbound",
        pkgConfig: "libunbound",
        providers: [
            .brew(["unbound"])
        ]
    ),
    .target(
      name: "DKIMVerifier",
      dependencies: [
        "RegularExpressions", "Peppermint", "SwiftParsec",
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "_CryptoExtras", package: "swift-crypto"),
      ]),
    .target(
      name: "DKIMVerifierDNS_dnssd",
      dependencies: ["DKIMVerifier"]),
    .target(
      name: "DKIMVerifierDNS_unbound",
      dependencies: ["DKIMVerifier", "libunbound"]),
    .target(
      name: "DKIMVerifierToolBase",
      dependencies: [
        "DKIMVerifier",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
      ]),
    .target(
      name: "DKIMVerifierTool",
      dependencies: [
        "DKIMVerifierToolBase",
      ]),
    .target(
      name: "DKIMVerifierTool_dnssd",
      dependencies: [
        "DKIMVerifierToolBase",
        "DKIMVerifierDNS_dnssd"
      ]),
    .target(
      name: "DKIMVerifierTool_unbound",
      dependencies: [
        "DKIMVerifierToolBase",
        "DKIMVerifierDNS_unbound"
      ]),
    .testTarget(
      name: "DKIMVerifierTests",
      dependencies: ["DKIMVerifier"],
      resources: [
        .process("Resources")
      ]),
  ]
)
