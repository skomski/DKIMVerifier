import XCTest

@testable import DKIMVerifier

final class CanonicalizationTests: XCTestCase {

  func testSimpleBodyTests() {
    XCTAssertEqual(
      try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: "dada\r\n"), "dada\r\n")
    XCTAssertEqual(try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: ""), "\r\n")
    XCTAssertEqual(try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: "\r\n"), "\r\n")
    XCTAssertEqual(try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: "\r\n\r\n"), "\r\n")
    XCTAssertEqual(
      try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: "\r\n \r\n"), "\r\n \r\n")
    XCTAssertEqual(
      try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: "\r\n\r\n  dada\r\n\r\n"),
      "\r\n\r\n  dada\r\n")
    XCTAssertEqual(
      try SimpleCanonicalizationBodyAlgorithm.canonicalize(
        body: "\r\n\r\n \r\n\r\n dada\r\n\r\n\r\n\r\n"), "\r\n\r\n \r\n\r\n dada\r\n")
  }
}
