import XCTest

@testable import DKIMVerifier

final class DKIMVerifierTests: XCTestCase {
  func GetDnsKey(domain: String) throws -> String? {
    let dnsKeyFilePaths = Bundle.module.paths(forResourcesOfType: "dns", inDirectory: nil)

    for dnsKeyFilePath in dnsKeyFilePaths {
      if dnsKeyFilePath.contains(domain) {
        return try String(
          contentsOf: URL(fileURLWithPath: dnsKeyFilePath), encoding: .utf8)
      }
    }

    XCTFail("unknown dns domain")
    return nil
  }

  func testCompleteEmails() {
    let emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)

    var total_emails = 0
    var valid_emails = 0
    var valid_insecure_emails = 0
    var error_emails = 0
    var no_signature_emails = 0

    for emailFilePath in emailFilePaths {
      do {
        let email_raw = try String(
          contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

        let expected_result: DKIMVerifier.DKIMResult
        switch emailFilePath {
        case _ where emailFilePath.contains("error_invalid_without_header"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Error(
              DKIMVerifier.DKIMError.invalidRFC822Headers(message: "invalid email without header")))
          error_emails += 1
        case _ where emailFilePath.contains("unsigned"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.NoSignature)
          no_signature_emails += 1
        case _ where emailFilePath.contains("sha1_length"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([
                DKIMVerifier.DKIMRisks.UsingSHA1, DKIMVerifier.DKIMRisks.UsingLengthParameter,
              ])))
          valid_insecure_emails += 1
        case _ where emailFilePath.contains("sha1"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([DKIMVerifier.DKIMRisks.UsingSHA1])))
          valid_insecure_emails += 1
        default:
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid)
          valid_emails += 1
        }

        XCTAssertEqual(
          DKIMVerifier.verify(dnsLoopupTxtFunction: GetDnsKey, email_raw: email_raw),
          expected_result, emailFilePath)
      } catch {
        XCTFail("email \(emailFilePath) should not throw an error: \(error)")
      }
      total_emails += 1
    }

    XCTAssertEqual(total_emails, emailFilePaths.count)
    XCTAssertEqual(total_emails, 9)
    XCTAssertEqual(error_emails, 1)
    XCTAssertEqual(no_signature_emails, 1)
    XCTAssertEqual(valid_insecure_emails, 2)
    XCTAssertEqual(valid_emails, 5)
    XCTAssertEqual(
      valid_emails + valid_insecure_emails + error_emails + no_signature_emails, total_emails)
  }
}
