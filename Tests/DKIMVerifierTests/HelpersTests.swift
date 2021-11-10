import XCTest

@testable import DKIMVerifier

final class HelpersTests: XCTestCase {

  func testTrailingTrimTests() {
    XCTAssertEqual(" sads ".trailingTrim(.whitespacesAndNewlines), " sads")
    XCTAssertEqual("\nsads\n".trailingTrim(.whitespacesAndNewlines), "\nsads")
    XCTAssertEqual("\n".trailingTrim(.whitespacesAndNewlines), "")
    XCTAssertEqual("ads".trailingTrim(.whitespacesAndNewlines), "ads")
  }

  func testParseEmailFromField() {
    XCTAssertEqual(DKIMVerifier.parseEmailFromField(raw_from_field: ""), nil)
    XCTAssertEqual(DKIMVerifier.parseEmailFromField(raw_from_field: "blabla"), nil)
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(raw_from_field: "blabla <hallo@skomski.com>"),
      "hallo@skomski.com")
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(raw_from_field: "\"blabla\" <hallo@skomski.com>"),
      "hallo@skomski.com")
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(
        raw_from_field: #""Giant; \"Big\" Box" <sysservices@example.net>"#),
      "sysservices@example.net")
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(raw_from_field: "hallo@skomski.com"), "hallo@skomski.com")
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(raw_from_field: " Joe SixPack <joe@football.example.com>"),
      "joe@football.example.com")
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(raw_from_field: "Joe SixPack <joe@football.example.com>"),
      "joe@football.example.com")
    
    XCTAssertEqual(
      DKIMVerifier.parseEmailFromField(raw_from_field: "IT-Helpcenter <it-helpcenter@HTW-Berlin.de>"),
      "it-helpcenter@HTW-Berlin.de")
  }

  func testParseDomainFromEmail() {
    XCTAssertEqual(DKIMVerifier.parseDomainFromEmail(email: ""), nil)
    XCTAssertEqual(DKIMVerifier.parseDomainFromEmail(email: "blabla"), nil)
    XCTAssertEqual(DKIMVerifier.parseDomainFromEmail(email: "hallo@skomski.com"), "skomski.com")
    XCTAssertEqual(DKIMVerifier.parseDomainFromEmail(email: "example.net"), nil)
    XCTAssertEqual(
      DKIMVerifier.parseDomainFromEmail(email: "pseudo@subdomain.example.net"),
      "subdomain.example.net")
    XCTAssertEqual(DKIMVerifier.parseDomainFromEmail(email: "hello@ä.example.net"), "ä.example.net")
    XCTAssertEqual(
      DKIMVerifier.parseDomainFromEmail(email: "it-helpcenter@HTW-Berlin.de"),
      "htw-berlin.de")
  }

  func testRFC822MessageParsing() {
    let simple_message = """
      help: 1
        2

      3
      """
    XCTAssertEqual(
      try DKIMVerifier.parseRFC822Message(message: simple_message).0,
      [KeyValue(key: "help", value: " 1\r\n  2\r\n")])
    XCTAssertEqual(try DKIMVerifier.parseRFC822Message(message: simple_message).1, "3")

    let multiple_headers = """
      habba:1
      babaB:2
      DDD: 3
      """
    XCTAssertEqual(
      try DKIMVerifier.parseRFC822Message(message: multiple_headers).0,
      [
        KeyValue(key: "habba", value: "1\r\n"),
        KeyValue(key: "babaB", value: "2\r\n"),
        KeyValue(key: "DDD", value: " 3\r\n"),
      ])
    XCTAssertEqual(try DKIMVerifier.parseRFC822Message(message: multiple_headers).1, "")

    let duplicate_headers = """
      habba:1
      habba:1
      habbA:1
       d

      duplicate_headers

      """
    XCTAssertEqual(
      try DKIMVerifier.parseRFC822Message(message: duplicate_headers).0,
      [
        KeyValue(key: "habba", value: "1\r\n"),
        KeyValue(key: "habba", value: "1\r\n"),
        KeyValue(key: "habbA", value: "1\r\n d\r\n"),
      ])
    XCTAssertEqual(
      try DKIMVerifier.parseRFC822Message(message: duplicate_headers).1, "duplicate_headers\r\n")
  }

  func testParseTagValueList() {
    XCTAssertEqual(try DKIMVerifier.parseTagValueList(raw_list: "help=1"), ["help": "1"])
    XCTAssertEqual(
      try DKIMVerifier.parseTagValueList(raw_list: "helP=1; Otto=2"), ["helP": "1", "Otto": "2"])
    XCTAssertEqual(
      try DKIMVerifier.parseTagValueList(raw_list: "helP=1; Otto= 2"), ["helP": "1", "Otto": "2"])
    XCTAssertEqual(
      try DKIMVerifier.parseTagValueList(raw_list: "helP=1; Otto= 2 2 "),
      ["helP": "1", "Otto": "2 2"])
    XCTAssertEqual(
      try DKIMVerifier.parseTagValueList(raw_list: "helP=1; Otto= 2 2 ;"),
      ["helP": "1", "Otto": "2 2"])
    XCTAssertEqual(
      try DKIMVerifier.parseTagValueList(raw_list: "helP=1; Otto= 2 2 ;"),
      ["helP": "1", "Otto": "2 2"])
    XCTAssertEqual(
      try DKIMVerifier.parseTagValueList(raw_list: "helP=1; Otto= 2\n2\n ;"),
      ["helP": "1", "Otto": "2\n2"])

    XCTAssertThrowsError(
      try DKIMVerifier.parseTagValueList(raw_list: "help=1; help=2"), "duplicate value"
    ) { error in
      XCTAssertEqual(
        error as! DKIMVerifier.DKIMError,
        DKIMVerifier.DKIMError.TagValueListParsingError(message: "duplicate key: help"))
    }

    XCTAssertThrowsError(
      try DKIMVerifier.parseTagValueList(raw_list: "help=;"), "no value for key help"
    ) { error in
      XCTAssertEqual(
        error as! DKIMVerifier.DKIMError,
        DKIMVerifier.DKIMError.TagValueListParsingError(message: "no value for key: help"))
    }

    XCTAssertThrowsError(
      try DKIMVerifier.parseTagValueList(raw_list: "help="), "no value for key help"
    ) { error in
      XCTAssertEqual(
        error as! DKIMVerifier.DKIMError,
        DKIMVerifier.DKIMError.TagValueListParsingError(message: "no value for key: help"))
    }
  }
}
