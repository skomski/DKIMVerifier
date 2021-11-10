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

  func testDMARCEmail() {
    let emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)
    let emailFilePath = emailFilePaths.first(where: { $0.contains("multiple_signatures") })!

    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

      let result = DKIMVerifier.verifyDKIMSignatures(
        dnsLoopupTxtFunction: GetDnsKey, email_raw: email_raw, verifyDMARC: true)

      var expected_result = DKIMVerifier.DKIMSignatureResult.init(
        status: DKIMVerifier.DKIMSignatureStatus.Valid)
      XCTAssertEqual(result.signatures.count, 2, emailFilePath)
      XCTAssertEqual(result.signatures[0].status, expected_result.status, emailFilePath)
      expected_result = DKIMVerifier.DKIMSignatureResult.init(
        status: DKIMVerifier.DKIMSignatureStatus.Insecure([
          DKIMRisks.InsecureKeySize(size: 1024, expected: 2048)
        ]))
      XCTAssertEqual(result.signatures[1].status, expected_result.status, emailFilePath)
      XCTAssertEqual(result.status, DKIMStatus.Valid)
      XCTAssertEqual(result.DMARCResult?.validDKIMIdentifierAlignment, true)
      XCTAssertEqual(result.DMARCResult?.entry.dkimAlignmentMode, AlignmentMode.Strict)

    } catch {
      XCTFail("email \(emailFilePath) should not throw an error: \(error)")
    }

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

        let result = DKIMVerifier.verifyDKIMSignatures(
          dnsLoopupTxtFunction: GetDnsKey, email_raw: email_raw)

        if emailFilePath.contains("unsigned") {
          XCTAssertEqual(result.signatures.count, 0, emailFilePath)
          XCTAssertEqual(result.status, DKIMVerifier.DKIMStatus.Error(DKIMError.NoSignature))
          XCTAssertEqual(result.emailFromSender, "Joe SixPack <joe@football.example.com>")
          no_signature_emails += 1
        } else if emailFilePath.contains("error_invalid_without_header") {
          XCTAssertEqual(result.signatures.count, 0, emailFilePath)
          let expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Error(
              DKIMVerifier.DKIMError.InvalidRFC5322Headers(message: "invalid email without header"))
          )
          XCTAssertEqual(result, expected_result)
          error_emails += 1
        } else if emailFilePath.contains("multiple_signatures") {

          var expected_result = DKIMVerifier.DKIMSignatureResult.init(
            status: DKIMVerifier.DKIMSignatureStatus.Valid)
          XCTAssertEqual(result.signatures.count, 2, emailFilePath)
          XCTAssertEqual(result.signatures[0].status, expected_result.status, emailFilePath)
          expected_result = DKIMVerifier.DKIMSignatureResult.init(
            status: DKIMVerifier.DKIMSignatureStatus.Insecure([
              DKIMRisks.InsecureKeySize(size: 1024, expected: 2048)
            ]))
          XCTAssertEqual(result.signatures[1].status, expected_result.status, emailFilePath)
          XCTAssertEqual(result.status, DKIMStatus.Valid)
          valid_emails += 1
        } else {
          XCTAssertEqual(result.signatures.count, 1, emailFilePath)

          let expected_result: DKIMVerifier.DKIMSignatureResult
          switch emailFilePath {
          case _ where emailFilePath.contains("insecure_key_size"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMVerifier.DKIMError.PublicKeyWithIncorrectParameters))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.contains("revoked"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMVerifier.DKIMError.PublicKeyRevoked))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.contains("wrong_signature"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMVerifier.DKIMError.SignatureDoesNotMatch))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.contains("sha1_length"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                Set.init([
                  DKIMVerifier.DKIMRisks.UsingSHA1,
                  DKIMVerifier.DKIMRisks.UsingLengthParameter,
                  DKIMVerifier.DKIMRisks.SDIDNotEqualToFrom(
                    sdid: "example.com", fromDomain: "football.example.com"),
                ])))

            XCTAssertEqual(result.signatures[0].info!.version, 1)
            XCTAssertEqual(
              result.signatures[0].info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA1)
            XCTAssertEqual(
              result.signatures[0].info!.signature,
              "FohDk4geyk/oJ+G9HmwzqLknTHxtZkWjZ1c8xZ/gf5+Ni+vyQe2HFd0spvQqoRBY8AXMNQiUX309wRgyFmoHpQKlXnbsxvG4nA/bCZ2HJCiijYV2RRoVL0QuMVMugTSWYBR4qJteXxwKwFARKbMX9K0mDQtLBcQAMNfO3bBNToc="
            )
            XCTAssertEqual(
              result.signatures[0].info!.headerCanonicalization,
              DKIMVerifier.DKIMCanonicalization.Relaxed)
            XCTAssertEqual(
              result.signatures[0].info!.bodyCanonicalization,
              DKIMVerifier.DKIMCanonicalization.Simple)
            XCTAssertEqual(result.signatures[0].info!.sdid, "example.com")
            XCTAssertEqual(
              result.signatures[0].info!.signedHeaderFields,
              ["from", "to", "subject", "date", "message-id", "from"])
            XCTAssertEqual(result.signatures[0].info!.domainSelector, "selector")
            XCTAssertEqual(
              result.signatures[0].info!.publicKeyQueryMethod,
              DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)

            XCTAssertEqual(result.signatures[0].info!.auid, "@example.com")
            XCTAssertEqual(result.extractedDomainFromSender, "football.example.com")
            XCTAssertEqual(result.signatures[0].info!.sdid, "example.com")
            XCTAssertEqual(result.signatures[0].info!.bodyLength, 55)
            XCTAssertEqual(
              result.signatures[0].info!.signatureTimestamp,
              Date(timeIntervalSince1970: 1_627_477_130))
            XCTAssertEqual(result.signatures[0].info!.signatureExpiration, nil)
            XCTAssertEqual(result.signatures[0].info!.copiedHeaderFields, nil)
            valid_insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Insecure)
          case _ where emailFilePath.contains("sha1"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                Set.init([
                  DKIMVerifier.DKIMRisks.UsingSHA1,
                  DKIMVerifier.DKIMRisks.SDIDNotEqualToFrom(
                    sdid: "example.com", fromDomain: "football.example.com"),
                ])))

            XCTAssertEqual(result.signatures[0].info!.version, 1)
            XCTAssertEqual(
              result.signatures[0].info!.publicKeyQueryMethod,
              DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)
            XCTAssertEqual(
              result.signatures[0].info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA1)
            valid_insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Insecure)
          case _ where emailFilePath.contains("only_from"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                Set.init([
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "subject"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "date"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "to"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "message-id"),
                  DKIMVerifier.DKIMRisks.SDIDNotEqualToFrom(
                    sdid: "custom.com", fromDomain: "football.example.com"),
                  DKIMVerifier.DKIMRisks.InsecureKeySize(size: 1024, expected: 2048),
                ])))

            XCTAssertEqual(result.signatures[0].info!.version, 1)
            XCTAssertEqual(
              result.signatures[0].info!.publicKeyQueryMethod,
              DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)
            XCTAssertEqual(
              result.signatures[0].info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA256)
            XCTAssertEqual(
              result.signatures[0].info!.signedHeaderFields,
              ["from"])
            valid_insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Insecure)
          case _ where emailFilePath.contains("mubi"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                Set.init([
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "date"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "message-id"),
                  DKIMVerifier.DKIMRisks.InsecureKeySize(size: 1024, expected: 2048),
                ])))
            XCTAssertEqual(result.extractedDomainFromSender, "mubi.com")
            valid_insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Insecure)
          default:
            if result.signatures[0].info!.rsaKeySizeInBits ?? 2048 < 2048 {
              XCTAssertEqual(result.signatures[0].info!.rsaKeySizeInBits!, 1024)
              expected_result = DKIMVerifier.DKIMSignatureResult.init(
                status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                  Set.init([
                    DKIMVerifier.DKIMRisks.InsecureKeySize(size: 1024, expected: 2048)
                  ])))
              valid_insecure_emails += 1
            } else {
              XCTAssertEqual(result.status, DKIMStatus.Valid)
              expected_result = DKIMVerifier.DKIMSignatureResult.init(
                status: DKIMVerifier.DKIMSignatureStatus.Valid)
              valid_emails += 1
            }
            XCTAssertEqual(result.signatures[0].info!.version, 1)
            XCTAssertEqual(
              result.signatures[0].info!.publicKeyQueryMethod,
              DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)

            if emailFilePath.contains("ed25519") {
              XCTAssertEqual(result.signatures[0].info!.rsaKeySizeInBits, nil)
              XCTAssertEqual(
                result.signatures[0].info!.algorithm,
                DKIMVerifier.DKIMSignatureAlgorithm.Ed25519_SHA256)
            } else if emailFilePath.contains("rsa_sha256") {
              XCTAssertEqual(result.signatures[0].info!.rsaKeySizeInBits!, 1024)
              XCTAssertEqual(
                result.signatures[0].info!.algorithm, DKIMVerifier.DKIMSignatureAlgorithm.RSA_SHA256
              )
            } else {
              XCTFail("invalid valid signature algorithm")
            }
          }

          XCTAssertEqual(result.signatures.count, 1, emailFilePath)
          XCTAssertEqual(result.signatures[0].status, expected_result.status, emailFilePath)
        }
      } catch {
        XCTFail("email \(emailFilePath) should not throw an error: \(error)")
      }
      total_emails += 1
    }

    XCTAssertEqual(total_emails, emailFilePaths.count)
    XCTAssertEqual(total_emails, 14)
    XCTAssertEqual(error_emails, 4)
    XCTAssertEqual(no_signature_emails, 1)
    XCTAssertEqual(valid_insecure_emails, 6)
    XCTAssertEqual(valid_emails, 3)
    XCTAssertEqual(
      valid_emails + valid_insecure_emails + error_emails + no_signature_emails, total_emails)
  }
}
