import XCTest

@testable import DKIMVerifier

final class CanonicalizationTests: XCTestCase {

  func testRelaxedBodyTests() {
    XCTAssertEqual(
      try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: ""), "")
    XCTAssertEqual(try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: "C\r\n"), "C\r\n")
    XCTAssertEqual(try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: "C \r\n"), "C\r\n")
    XCTAssertEqual(try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: " C \r\n"), " C\r\n")
    XCTAssertEqual(
      try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: " C\t \r\n"), " C\r\n")
    XCTAssertEqual(
      try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: " C\t \r\n D\t\t \r\nE"),
      " C\r\n D\r\nE")
  }

  func testRelaxedHeaderTests() {
    XCTAssertEqual(
      try RelaxedCanonicalizationHeaderAlgorithm.canonicalize(headers: [
        KeyValue(key: "HABBA", value: " 1\r\n"),
        KeyValue(key: "habba ", value: " 1\t\r\n\t2  \r\n"),
        KeyValue(key: "habbA", value: "1")
      ]),
      [
        KeyValue(key: "habba", value: "1\r\n"),
        KeyValue(key: "habba", value: "1 2\r\n"),
        KeyValue(key: "habba", value: "1\r\n")
      ])
  }

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
