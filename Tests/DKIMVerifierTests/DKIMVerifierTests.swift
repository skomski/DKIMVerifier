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

        let result = DKIMVerifier.verify(dnsLoopupTxtFunction: GetDnsKey, email_raw: email_raw)

        let expected_result: DKIMVerifier.DKIMResult
        switch emailFilePath {
        case _ where emailFilePath.contains("error_invalid_without_header"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Error(
              DKIMVerifier.DKIMError.InvalidRFC822Headers(message: "invalid email without header")))
          error_emails += 1
        case _ where emailFilePath.contains("wrong_signature"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Invalid(
              DKIMVerifier.DKIMError.SignatureDoesNotMatch))
          error_emails += 1
        case _ where emailFilePath.contains("unsigned"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.NoSignature)
          XCTAssertEqual(result.email_from_sender, "Joe SixPack <joe@football.example.com>")
          no_signature_emails += 1
        case _ where emailFilePath.contains("sha1_length"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([
                DKIMVerifier.DKIMRisks.UsingSHA1, DKIMVerifier.DKIMRisks.UsingLengthParameter,
              ])))

          XCTAssertEqual(result.info!.version, 1)
          XCTAssertEqual(result.info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA1)
          XCTAssertEqual(
            result.info!.signature,
            "FohDk4geyk/oJ+G9HmwzqLknTHxtZkWjZ1c8xZ/gf5+Ni+vyQe2HFd0spvQqoRBY8AXMNQiUX309wRgyFmoHpQKlXnbsxvG4nA/bCZ2HJCiijYV2RRoVL0QuMVMugTSWYBR4qJteXxwKwFARKbMX9K0mDQtLBcQAMNfO3bBNToc="
          )
          XCTAssertEqual(
            result.info!.headerCanonicalization, DKIMVerifier.DKIMCanonicalization.Relaxed)
          XCTAssertEqual(
            result.info!.bodyCanonicalization, DKIMVerifier.DKIMCanonicalization.Simple)
          XCTAssertEqual(result.info!.sdid, "example.com")
          XCTAssertEqual(
            result.info!.signedHeaderFields,
            ["from", "to", "subject", "date", "message-id", "from"])
          XCTAssertEqual(result.info!.domainSelector, "selector")
          XCTAssertEqual(
            result.info!.publicKeyQueryMethod, DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)

          XCTAssertEqual(result.info!.auid, "@example.com")
          XCTAssertEqual(result.info!.bodyLength, 55)
          XCTAssertEqual(
            result.info!.signatureTimestamp, Date(timeIntervalSince1970: 1_627_477_130))
          XCTAssertEqual(result.info!.signatureExpiration, nil)
          XCTAssertEqual(result.info!.copiedHeaderFields, nil)
          valid_insecure_emails += 1
        case _ where emailFilePath.contains("sha1"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([DKIMVerifier.DKIMRisks.UsingSHA1])))

          XCTAssertEqual(result.info!.version, 1)
          XCTAssertEqual(
            result.info!.publicKeyQueryMethod, DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)
          XCTAssertEqual(result.info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA1)
          valid_insecure_emails += 1
        case _ where emailFilePath.contains("only_from"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([
                DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "subject"),
                DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "date"),
              ])))

          XCTAssertEqual(result.info!.version, 1)
          XCTAssertEqual(
            result.info!.publicKeyQueryMethod, DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)
          XCTAssertEqual(result.info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA256)
          XCTAssertEqual(
            result.info!.signedHeaderFields,
            ["from"])
          valid_insecure_emails += 1
        case _ where emailFilePath.contains("mubi"):
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid_Insecure(
              Set.init([DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "date")])))
          valid_insecure_emails += 1
        default:
          expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Valid)
          XCTAssertEqual(result.info!.version, 1)
          XCTAssertEqual(
            result.info!.publicKeyQueryMethod, DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)

          if emailFilePath.contains("ed25519") {
            XCTAssertEqual(
              result.info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.Ed25519_SHA256)
          } else if emailFilePath.contains("rsa_sha256") {
            XCTAssertEqual(result.info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA256)
          } else {
            XCTFail("invalid valid signature algorithm")
          }

          valid_emails += 1
        }

        XCTAssertEqual(result.status, expected_result.status, emailFilePath)
      } catch {
        XCTFail("email \(emailFilePath) should not throw an error: \(error)")
      }
      total_emails += 1
    }

    XCTAssertEqual(total_emails, emailFilePaths.count)
    XCTAssertEqual(total_emails, 11)
    XCTAssertEqual(error_emails, 2)
    XCTAssertEqual(no_signature_emails, 1)
    XCTAssertEqual(valid_insecure_emails, 4)
    XCTAssertEqual(valid_emails, 4)
    XCTAssertEqual(
      valid_emails + valid_insecure_emails + error_emails + no_signature_emails, total_emails)
  }
}
