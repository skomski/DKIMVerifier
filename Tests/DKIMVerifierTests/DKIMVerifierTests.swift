import XCTest

@testable import DKIMVerifier

final class DKIMVerifierTests: XCTestCase {
  static public var rfc6376_path: String = Bundle.module.path(
    forResource: "rfc6376", ofType: "msg")!
  static public var rfc6376_signed_path: String = Bundle.module.path(
    forResource: "rfc6376.signed.rsa", ofType: "msg")!
  static public var rfc6376_signed_sha1_path: String = Bundle.module.path(
    forResource: "rfc6376.signed.sha1", ofType: "msg")!
  static public var testkeydns_entry: String = Bundle.module.path(
    forResource: "testkeydnsentry", ofType: "txt")!
  static public var spam_eml: String = Bundle.module.path(forResource: "spam", ofType: "eml")!
  static public var rfc6376_signed_ed25519_path: String = Bundle.module.path(
    forResource: "rfc6376.signed.ed25519", ofType: "msg")!
  static public var rfc6376_signed_relaxed_path: String = Bundle.module.path(
    forResource: "rfc6376.signed.relaxed", ofType: "msg")!
  static public var mubi_path: String = Bundle.module.path(forResource: "mubi", ofType: "eml")!

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
        DKIMVerifier.verify(dnsLoopupTxtFunction: rfcDnsEntryFunction, email_raw: email_raw),
        DKIMVerifier.DKIMResult.init(
          status: DKIMVerifier.DKIMStatus.Valid))
    } catch {
      XCTFail("test rsa email should verify: \(error)")
    }
  }

  func testRFC6376Sha1TestEmail() {
    let TxtAnswerFunction = {
      (domain: String) in
      Optional(
        "v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6aakWzruYAKX9OdOdSHMemqVdGQurNYLC1H7O/T2LQIHVbkKF6KKjlgFM7lr8skfZMhJe/KRGMvVjCV5ZakZIGeP3Hi1qXCEvmjS4ElpMPMPyPrZigt95ipqywPYZJWHbRiJ085VdkSCtLUvo5sypA0nTJeynEouAN+/wBaCO6QIDAQAB"
      )
    }
    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.rfc6376_signed_sha1_path),
        encoding: .ascii)
      XCTAssertEqual(
        DKIMVerifier.verify(dnsLoopupTxtFunction: TxtAnswerFunction, email_raw: email_raw),
        DKIMVerifier.DKIMResult.init(
          status: DKIMVerifier.DKIMStatus.Valid_Insecure(
            Set<DKIMRisks>.init(arrayLiteral: DKIMRisks.UsingSHA1))))
    } catch {
      XCTFail("RFC6376Sha1Test email should verify: \(error)")
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
        DKIMVerifier.verify(dnsLoopupTxtFunction: TxtAnswerFunction, email_raw: email_raw),
        DKIMVerifier.DKIMResult.init(
          status: DKIMVerifier.DKIMStatus.Valid))
    } catch {
      XCTFail("RFC6376Ed25519Test email should verify: \(error)")
    }
  }

  func testRFC6376Ed25519RelaxedTestEmail() {
    let TxtAnswerFunction = {
      (domain: String) in
      Optional(
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
      )
    }
    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.rfc6376_signed_relaxed_path),
        encoding: .ascii)
      XCTAssertEqual(
        DKIMVerifier.verify(dnsLoopupTxtFunction: TxtAnswerFunction, email_raw: email_raw),
        DKIMVerifier.DKIMResult.init(
          status: DKIMVerifier.DKIMStatus.Valid))
    } catch {
      XCTFail("RFC6376Ed25519RelaxedTest email should verify: \(error)")
    }
  }

  func testMubiEmail() {
    let TxtAnswerFunction = {
      (domain: String) in
      Optional(
        """
        k=rsa; t=s;
        p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmp+fPfv02EvoCedCK5ZEFAvSgMuY4Trib7M/h5rp8ZXM3qVhRRAs8Qi1iPsdZLQ0uzYLQo9Kkz3d+7tN/xjrMRMZ3IQJ7RsyPxStpLyWCn8z6CYYbgWNG7IgPwCBafjk0achPWaGwdRfyW0R9V5QTF/E7urCocVvA4833omytewIDAQAB
        """
      )
    }
    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: DKIMVerifierTests.mubi_path),
        encoding: .ascii)
      XCTAssertEqual(
        DKIMVerifier.verify(dnsLoopupTxtFunction: TxtAnswerFunction, email_raw: email_raw),
        DKIMVerifier.DKIMResult.init(
          status: DKIMVerifier.DKIMStatus.Valid))
    } catch {
      XCTFail("Mubi email should verify: \(error)")
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
        DKIMVerifier.verify(dnsLoopupTxtFunction: spamTxtAnswerFunction, email_raw: email_raw),
        DKIMVerifier.DKIMResult.init(
          status: DKIMVerifier.DKIMStatus.Valid))
    } catch {
      XCTFail("spam email should verify: \(error)")
    }
  }
}
