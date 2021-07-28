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

    var counter = 0
    for emailFilePath in emailFilePaths {
      do {
        let email_raw = try String(
          contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

        let expected_result: DKIMVerifier.DKIMResult
        switch emailFilePath {
        case _ where emailFilePath.contains("unsigned"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.NoSignature)
        case _ where emailFilePath.contains("sha1"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([DKIMVerifier.DKIMRisks.UsingSHA1])))
        default:
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid)
        }

        XCTAssertEqual(
          DKIMVerifier.verify(dnsLoopupTxtFunction: GetDnsKey, email_raw: email_raw),
          expected_result, emailFilePath)
      } catch {
        XCTFail("email should not throw an error: \(error)")
      }
      counter += 1
    }

    XCTAssertEqual(counter, emailFilePaths.count)
    XCTAssertEqual(counter, 7)
  }
}
