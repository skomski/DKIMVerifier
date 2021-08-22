import XCTest

@testable import DKIMVerifier

final class DMARCTests: XCTestCase {

  func getDMARCNoFailDnsEntry(domain: String) throws -> String? {
    if domain == "_dmarc.test.com" {
      return "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@test.com; adkim=s;"
    }

    if domain == "_dmarc.testdefault.com" {
      return "v=DMARC1; p=reject;"
    }

    XCTFail("unknown dns domain")
    return nil
  }

  func testDMARCQueryNoFail() {
    do {
      let result = try queryDMARC(dnsLoopupTxtFunction: getDMARCNoFailDnsEntry, domain: "test.com")
      XCTAssertEqual(result.version, DMARCVersion.One)
      XCTAssertEqual(result.mailReceiverPolicy, MailReceiverPolicy.None)
      XCTAssertEqual(result.subdomainMailReceiverPolicy, MailReceiverPolicy.Quarantine)
      XCTAssertEqual(result.dkimAlignmentMode, AlignmentMode.Strict)
    } catch {
      XCTFail("dns dmarc should not throw an error: \(error)")
    }
  }

  func testDMARCQueryNoFailDefault() {
    do {
      let result = try queryDMARC(
        dnsLoopupTxtFunction: getDMARCNoFailDnsEntry, domain: "testdefault.com")
      XCTAssertEqual(result.version, DMARCVersion.One)
      XCTAssertEqual(result.mailReceiverPolicy, MailReceiverPolicy.Reject)
      XCTAssertEqual(result.subdomainMailReceiverPolicy, MailReceiverPolicy.Reject)
      XCTAssertEqual(result.dkimAlignmentMode, AlignmentMode.Relaxed)
    } catch {
      XCTFail("dns dmarc should not throw an error: \(error)")
    }
  }
}
