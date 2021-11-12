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
      .upToNextMinor(from: "2.2.0")),
    .package(
      name: "swift-argument-parser", url: "https://github.com/apple/swift-argument-parser",
      .upToNextMinor(from: "1.0.2")),
      .package(name: "swift-crypto", url: "https://github.com/apple/swift-crypto", .upToNextMinor(from: "2.0.1")),
    .package(name: "TLDExtract", url: "https://github.com/gumob/TLDExtractSwift", .revision("8c051b60df00a3fd5c568bab657534857eb4287f")),
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
        "RegularExpressions", "TLDExtract",
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
