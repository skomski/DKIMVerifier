import XCTest

@testable import DKIMVerifier

final class DMARCTests: XCTestCase {

  func getDMARCNoFailDnsEntry(domain: String) throws -> DNSResult {
    if domain == "_dmarc.test.com" {
      return DNSResult.init(
        result: "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@test.com; adkim=s;",
        validatedWithDNSSEC: false)
    }

    if domain == "_dmarc.testdefault.com" {
      return DNSResult.init(result: "v=DMARC1; p=reject;", validatedWithDNSSEC: true)
    }

    XCTFail("unknown dns domain")
    return DNSResult(result: "", validatedWithDNSSEC: true)
  }

  func testDMARCQueryNoFail() {
    do {
      let (result, secure) = try queryDMARC(
        dnsLookupTxtFunction: getDMARCNoFailDnsEntry, domain: "test.com")
      XCTAssertEqual(result.version, DMARCVersion.One)
      XCTAssertEqual(result.mailReceiverPolicy, MailReceiverPolicy.None)
      XCTAssertEqual(result.subdomainMailReceiverPolicy, MailReceiverPolicy.Quarantine)
      XCTAssertEqual(result.dkimAlignmentMode, AlignmentMode.Strict)
      XCTAssertEqual(secure, false)
    } catch {
      XCTFail("dns dmarc should not throw an error: \(error)")
    }
  }

  func testDMARCQueryNoFailDefault() {
    do {
      let (result, secure) = try queryDMARC(
        dnsLookupTxtFunction: getDMARCNoFailDnsEntry, domain: "testdefault.com")
      XCTAssertEqual(result.version, DMARCVersion.One)
      XCTAssertEqual(result.mailReceiverPolicy, MailReceiverPolicy.Reject)
      XCTAssertEqual(result.subdomainMailReceiverPolicy, MailReceiverPolicy.Reject)
      XCTAssertEqual(result.dkimAlignmentMode, AlignmentMode.Relaxed)
      XCTAssertEqual(secure, true)
    } catch {
      XCTFail("dns dmarc should not throw an error: \(error)")
    }
  }
}
