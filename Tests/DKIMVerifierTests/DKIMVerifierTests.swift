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
        try DKIMVerifier.verify(dnsLoopupTxtFunction: rfcDnsEntryFunction, email_raw: email_raw),
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
        try DKIMVerifier.verify(dnsLoopupTxtFunction: TxtAnswerFunction, email_raw: email_raw),
        true)
    } catch {
      XCTFail("RFC6376Ed25519Test email should verify: \(error)")
    }
  }

  func testSpamEmail() {
    let spamTxtAnswerFunction = {
      (domain: String) in
      Optional(
        "v=DKIM1; k=rsa; s=email; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC82him/9TIsr8K2ZKn5qO5wjhf1S+AHUkaukIRwKu48Gw5SCGJRJY0z9TiS8Nxe58+MBs9jQLe8vM/v+3qgDHKs8WEaeWMi0HAfGvqCaPYLHGQkftyV6ph/zjW+Bjq4LUgWBZx641dD/bek4lNWW82IQ6iOhED7xQokqfuLXYsnwIDAQAB"
      )
    }
    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.spam_eml), encoding: .ascii)
      XCTAssertEqual(
        try DKIMVerifier.verify(dnsLoopupTxtFunction: spamTxtAnswerFunction, email_raw: email_raw),
        true)
    } catch {
      XCTFail("spam email should verify: \(error)")
    }
  }
}
