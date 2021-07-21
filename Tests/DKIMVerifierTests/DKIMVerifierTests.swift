import XCTest

@testable import DKIMVerifier

final class DKIMVerifierTests: XCTestCase {
  static public var rfc6376_path: String = Bundle.module.path(
    forResource: "rfc6376", ofType: "msg")!
  static public var rfc6376_signed_path: String = Bundle.module.path(
    forResource: "rfc6376.signed.rsa", ofType: "msg")!
  static public var testkeydns_entry: String = Bundle.module.path(
    forResource: "testkeydnsentry", ofType: "txt")!
  static public var spam_eml: String = Bundle.module.path(forResource: "spam", ofType: "eml")!
  static public var rfc6376_signed_ed25519_path: String = Bundle.module.path(
    forResource: "rfc6376.signed.ed25519", ofType: "msg")!

  func testTrailingTrimTests() {
    XCTAssertEqual(" sads ".trailingTrim(.whitespacesAndNewlines), " sads")
    XCTAssertEqual("\nsads\n".trailingTrim(.whitespacesAndNewlines), "\nsads")
    XCTAssertEqual("\n".trailingTrim(.whitespacesAndNewlines), "")
    XCTAssertEqual("ads".trailingTrim(.whitespacesAndNewlines), "ads")
  }

  func testRFC822MessageParsing() {
    let simple_message = """
      help: 1
        2

      3
      """
    XCTAssertEqual(
      try DKIMVerifier.parseRFC822Message(message: simple_message).0,
      [DKIMVerifier.KeyValue(key: "help", value: " 1\r\n  2\r\n")])
    XCTAssertEqual(try DKIMVerifier.parseRFC822Message(message: simple_message).1, "3")

    let multiple_headers = """
      habba:1
      babaB:2
      DDD: 3
      """
    XCTAssertEqual(
      try DKIMVerifier.parseRFC822Message(message: multiple_headers).0,
      [
        DKIMVerifier.KeyValue(key: "habba", value: "1\r\n"),
        DKIMVerifier.KeyValue(key: "babaB", value: "2\r\n"),
        DKIMVerifier.KeyValue(key: "DDD", value: " 3\r\n"),
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
        DKIMVerifier.KeyValue(key: "habba", value: "1\r\n"),
        DKIMVerifier.KeyValue(key: "habba", value: "1\r\n"),
        DKIMVerifier.KeyValue(key: "habbA", value: "1\r\n d\r\n"),
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
        DKIMVerifier.DKIMError.tagValueListParsingError(message: "duplicate key: help"))
    }

    XCTAssertThrowsError(
      try DKIMVerifier.parseTagValueList(raw_list: "help=;"), "no value for key help"
    ) { error in
      XCTAssertEqual(
        error as! DKIMVerifier.DKIMError,
        DKIMVerifier.DKIMError.tagValueListParsingError(message: "no value for key: help"))
    }

    XCTAssertThrowsError(
      try DKIMVerifier.parseTagValueList(raw_list: "help="), "no value for key help"
    ) { error in
      XCTAssertEqual(
        error as! DKIMVerifier.DKIMError,
        DKIMVerifier.DKIMError.tagValueListParsingError(message: "no value for key: help"))
    }
  }

  func testRFC6376RSATestEmail() {
    do {
      let dns_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.testkeydns_entry), encoding: .ascii)
      let rfcDnsEntryFunction = {
        (domain: String) in Optional(dns_raw)
      }
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.rfc6376_signed_path), encoding: .ascii)
      XCTAssertEqual(
        try DKIMVerifier(dnsLoopupTxtFunction: rfcDnsEntryFunction).verify(email_raw: email_raw),
        true)
    } catch {
      XCTFail("test rsa email should verify: \(error)")
    }
  }

  func testRFC6376Ed25519TestEmail() {
    let TxtAnswerFunction = {
      (domain: String) in
      Optional(
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
      )
    }
    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.rfc6376_signed_ed25519_path),
        encoding: .ascii)
      XCTAssertEqual(
        try DKIMVerifier(dnsLoopupTxtFunction: TxtAnswerFunction).verify(email_raw: email_raw),
        true)
    } catch {
      XCTFail("RFC6376Ed25519Test email should verify: \(error)")
    }
  }

  //  func testSpamEmail() {
  //    let spamTxtAnswerFunction = {
  //      (domain: String) in
  //      Optional(
  //        "v=DKIM1; k=rsa; s=email; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC82him/9TIsr8K2ZKn5qO5wjhf1S+AHUkaukIRwKu48Gw5SCGJRJY0z9TiS8Nxe58+MBs9jQLe8vM/v+3qgDHKs8WEaeWMi0HAfGvqCaPYLHGQkftyV6ph/zjW+Bjq4LUgWBZx641dD/bek4lNWW82IQ6iOhED7xQokqfuLXYsnwIDAQAB"
  //      )
  //    }
  //    do {
  //      let email_raw = try String(
  //        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.spam_eml), encoding: .ascii)
  //      XCTAssertEqual(
  //        try DKIMVerifier(dnsLoopupTxtFunction: spamTxtAnswerFunction).verify(email_raw: email_raw),
  //        true)
  //    } catch {
  //      XCTFail("spam email should verify: \(error)")
  //    }
  //  }
}
