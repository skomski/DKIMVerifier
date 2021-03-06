import Punycode
import XCTest

@testable import DKIMVerifier

final class DKIMVerifierTests: XCTestCase {
  func GetDnsKey(domain: String) throws -> DNSResult {
    let dnsKeyFilePaths = Bundle.module.paths(forResourcesOfType: "dns", inDirectory: nil)

    for dnsKeyFilePath in dnsKeyFilePaths {
      if dnsKeyFilePath.contains(domain.idnaDecoded!) {
        return try DNSResult.init(
          result: String(
            contentsOf: URL(fileURLWithPath: dnsKeyFilePath), encoding: .utf8),
          validatedWithDNSSEC: true)
      }
    }

    XCTFail("unknown dns domain \(domain)")
    return DNSResult.init(result: String(), validatedWithDNSSEC: true)
  }

  func testDMARCEmail() {
    let emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)
    let emailFilePath = emailFilePaths.first(where: { $0.hasSuffix("multiple_signatures.eml") })!

    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

      let result = DKIMVerifier.verifyDKIMSignatures(
        dnsLoopupTxtFunction: GetDnsKey, emailRaw: email_raw, verifyDMARCAlignment: true)

      var expected_result = DKIMVerifier.DKIMSignatureResult.init(
        status: DKIMVerifier.DKIMSignatureStatus.Valid)
      XCTAssertEqual(result.signatures.count, 2, emailFilePath)
      XCTAssertEqual(result.signatures[0].status, expected_result.status, emailFilePath)
      expected_result = DKIMVerifier.DKIMSignatureResult.init(
        status: DKIMVerifier.DKIMSignatureStatus.Valid)
      XCTAssertEqual(result.signatures[1].status, expected_result.status, emailFilePath)
      XCTAssertEqual(result.status, DKIMStatus.Valid)
      XCTAssertEqual(result.dmarcResult!.status, DMARCStatus.validDKIMIdentifierAlignment)
      XCTAssertEqual(result.dmarcResult!.entry!.dkimAlignmentMode, AlignmentMode.Strict)

    } catch {
      XCTFail("email \(emailFilePath) should not throw an error: \(error)")
    }

  }

  func testDuplicatedImportantHeaderEmail() {
    let emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)
    let emailFilePath = emailFilePaths.first(where: {
      $0.hasSuffix("duplicate_important_headers.eml")
    })!

    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

      let result = DKIMVerifier.verifyDKIMSignatures(
        dnsLoopupTxtFunction: GetDnsKey, emailRaw: email_raw, verifyDMARCAlignment: false)

      XCTAssertEqual(
        result.status,
        DKIMStatus.Error(DKIMError.ImportantHeaderMultipleTimesDetected(header: "subject")))
      XCTAssertEqual(result.signatures.count, 0, emailFilePath)
    } catch {
      XCTFail("email \(emailFilePath) should not throw an error: \(error)")
    }
  }

  func testMultipleSignaturesWithFail() {
    let emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)
    let emailFilePath = emailFilePaths.first(where: { $0.hasSuffix("multiple_signatures_fail.eml") }
    )!

    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

      func LocalGetDnsKey(domain: String) throws -> DNSResult {
        if domain == "test._domainkey.auidsub.com" {
          return DNSResult.init(
            result: "k=rsa; t=s; v=DKIM1; p=yi50DjK5O9pqbFpNHklsv9lqaS0ArSYu02qp1S0DW1Y=",
            validatedWithDNSSEC: false)
        }

        return try GetDnsKey(domain: domain)
      }

      let result = DKIMVerifier.verifyDKIMSignatures(
        dnsLoopupTxtFunction: LocalGetDnsKey, emailRaw: email_raw, verifyDMARCAlignment: false)

      XCTAssertEqual(result.status, DKIMVerifier.DKIMStatus.Valid)

      XCTAssertEqual(
        result.signatures[0].status,
        DKIMVerifier.DKIMSignatureResult.init(
          status: DKIMVerifier.DKIMSignatureStatus.Valid
        ).status, emailFilePath)

      XCTAssertEqual(
        result.signatures[1].status,
        DKIMVerifier.DKIMSignatureResult.init(
          status: DKIMVerifier.DKIMSignatureStatus.Error(DKIMError.SignatureDoesNotMatch)
        ).status, emailFilePath)

      XCTAssertEqual(
        result.signatures[2].status,
        DKIMVerifier.DKIMSignatureResult.init(
          status: DKIMVerifier.DKIMSignatureStatus.Error(
            DKIMError.AUIDDomainPartMustBeEqualToSDIDValidationError)
        ).status, emailFilePath)
    } catch {
      XCTFail("email \(emailFilePath) should not throw an error: \(error)")
    }
  }

  func testDKIMTestMode() {
    let emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)
    let emailFilePath = emailFilePaths.first(where: { $0.hasSuffix("multiple_signatures.eml") })!

    do {
      let email_raw = try String(
        contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

      func LocalGetDnsKey(domain: String) throws -> DNSResult {
        return DNSResult.init(
          result: "k=rsa; t=y; v=DKIM1; p=yi50DjK5O9pqbFpNHklsv9lqaS0ArSYu02qp1S0DW1Y=",
          validatedWithDNSSEC: false)
      }

      let result = DKIMVerifier.verifyDKIMSignatures(
        dnsLoopupTxtFunction: LocalGetDnsKey, emailRaw: email_raw, verifyDMARCAlignment: false)
      var expected_result = DKIMVerifier.DKIMSignatureResult.init(
        status: DKIMVerifier.DKIMSignatureStatus.Error(DKIMError.DKIMTestMode))
      XCTAssertEqual(result.signatures[0].status, expected_result.status, emailFilePath)
      expected_result = DKIMVerifier.DKIMSignatureResult.init(
        status: DKIMVerifier.DKIMSignatureStatus.Error(
          DKIMError.InvalidDNSEntry(
            message:
              "dns entry keyType rsa is not expected from DKIMSignature algorithm ed25519-sha256 (h)"
          )))
      XCTAssertEqual(result.signatures[1].status, expected_result.status, emailFilePath)
    } catch {
      XCTFail("email \(emailFilePath) should not throw an error: \(error)")
    }
  }

  func testCompleteEmails() {
    var emailFilePaths = Bundle.module.paths(forResourcesOfType: "eml", inDirectory: nil)

    // skip specific email - extern test: testMultipleSignaturesWithFail
    emailFilePaths = emailFilePaths.filter({ !$0.hasSuffix("multiple_signatures_fail.eml") })
    emailFilePaths = emailFilePaths.filter({ !$0.hasSuffix("duplicate_important_headers.eml") })

    var total_emails = 0
    var valid_emails = 0
    var insecure_emails = 0
    var error_emails = 0
    var no_signature_emails = 0

    for emailFilePath in emailFilePaths {
      do {
        let email_raw = try String(
          contentsOf: URL(fileURLWithPath: emailFilePath), encoding: .utf8)

        let result = DKIMVerifier.verifyDKIMSignatures(
          dnsLoopupTxtFunction: GetDnsKey, emailRaw: email_raw)

        if emailFilePath.hasSuffix("unsigned.eml") {
          XCTAssertEqual(result.signatures.count, 0, emailFilePath)
          XCTAssertEqual(result.status, DKIMVerifier.DKIMStatus.Error(DKIMError.NoSignature))
          XCTAssertEqual(result.emailFromSender, "Joe SixPack <joe@football.example.com>")
          no_signature_emails += 1
        } else if emailFilePath.hasSuffix("unsigned_idna.eml") {
          XCTAssertEqual(result.signatures.count, 0, emailFilePath)
          XCTAssertEqual(result.status, DKIMVerifier.DKIMStatus.Error(DKIMError.NoSignature))
          XCTAssertEqual(result.emailFromSender, "<j??e@??????.br??tzelein.com>")
          XCTAssertEqual(
            result.extractedDomainFromSenderIdnaEncoded, "xn--4ca9as.xn--brtzelein-w2a.com")
          no_signature_emails += 1
        } else if emailFilePath.hasSuffix("error_invalid_without_header.eml") {
          XCTAssertEqual(result.signatures.count, 0, emailFilePath)
          let expected_result = DKIMVerifier.DKIMResult.init(
            status: DKIMVerifier.DKIMStatus.Error(
              DKIMVerifier.DKIMError.InvalidRFC5322Headers(message: "invalid email without header"))
          )
          XCTAssertEqual(result, expected_result)
          error_emails += 1
        } else if emailFilePath.hasSuffix("multiple_signatures.eml") {

          var expected_result = DKIMVerifier.DKIMSignatureResult.init(
            status: DKIMVerifier.DKIMSignatureStatus.Valid)
          XCTAssertEqual(result.signatures.count, 2, emailFilePath)
          XCTAssertEqual(result.signatures[0].status, expected_result.status, emailFilePath)
          expected_result = DKIMVerifier.DKIMSignatureResult.init(
            status: DKIMVerifier.DKIMSignatureStatus.Valid)
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
                DKIMVerifier.DKIMError.PublicKeyWithIncorrectParameters(
                  message: "_RSA.Signing.PublicKey.init -> incorrectParameterSize")))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.hasSuffix("revoked.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMVerifier.DKIMError.PublicKeyRevoked))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.hasSuffix("wrong_signature.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMVerifier.DKIMError.SignatureDoesNotMatch))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.hasSuffix("sha256_length.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Valid)

            XCTAssertEqual(result.signatures[0].info!.version, 1)
            XCTAssertEqual(
              result.signatures[0].info!.signature,
              "DUGXJVvmNyERxMVBg1TtWU+WVrQ307Uf2wrFfZp2houvfpA8E6c/SUX3iQpU1HI3bssTJ"
                + "KXZhNoqg/PHXKysQJXSKOnXr/7L+yQf5pO/iSeItcm/EvPJPbQcbTH03I81Qse/2ZmcpR9o"
                + "MlH9hjBgmuVt0XYWeY3Gu+i3Ei9pBGslxzL0sWXBYDI995rIc4X6E10QSOvcHB990OhWXeL"
                + "l6GDdF980PN7zl8Shn5/izTFxf3vMkJmZ9Nc0ZGNTUMzXp0ZbEqfPgzRIO0P+NuJQUV5ew/"
                + "y7FRkLJCKn0nOUFUYTNwiDH85SPG/at7P6/vIwjir1cVHGd9zBJkSes1yvA5Pnxn/bCrS7H"
                + "EWQiXQIDjLObesWCMKx5RtcZhxLUSNH1SrXJvGPl0dktfOBiyZZSZVkKRdQyHriM9kLrPAo"
                + "igQtta1uEGPMNdQYTClibXqiXrLyD4gHyvdH0ayJC9uKYSkBLrqXP2E3xirVil0xIHlDBPm"
                + "305QJupyzIGt8+nqTgApD"
            )
            XCTAssertEqual(
              result.signatures[0].info!.headerCanonicalization,
              DKIMVerifier.DKIMCanonicalization.Relaxed)
            XCTAssertEqual(
              result.signatures[0].info!.bodyCanonicalization,
              DKIMVerifier.DKIMCanonicalization.Simple)
            XCTAssertEqual(result.signatures[0].info!.sdid, "football.example.com")
            XCTAssertEqual(
              result.signatures[0].info!.signedHeaderFields,
              ["from", "to", "subject", "date", "message-id", "from"])
            XCTAssertEqual(result.signatures[0].info!.domainSelector, "rsa3096")
            XCTAssertEqual(
              result.signatures[0].info!.publicKeyQueryMethod,
              DKIMVerifier.DKIMPublicKeyQueryMethod.DNSTXT)

            XCTAssertEqual(result.signatures[0].info!.auid, "@football.example.com")
            XCTAssertEqual(result.extractedDomainFromSender, "football.example.com")
            // XCTAssertEqual(result.signatures[0].info!.bodyLength, 55)
            XCTAssertEqual(
              result.signatures[0].info!.signatureTimestamp,
              Date(timeIntervalSince1970: 1_636_839_548))
            XCTAssertEqual(result.signatures[0].info!.signatureExpiration, nil)
            // XCTAssertEqual(result.signatures[0].info!.copiedHeaderFields, nil)
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Valid)
          case _ where emailFilePath.hasSuffix("sha256_length_invalid.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMVerifier.DKIMError.BodyHashDoesNotMatch(
                  message:
                    "provided hash 4bLNXImK9drULnmePzZNEBleUanJCX5PIsDIFoH4KTQ= not equal to calculated hash OEA7veIXkfRFlxj0oh6vlyQAzV1IgpgKSmGQW1Q+YIg="
                )))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.hasSuffix("sha256_expired.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Insecure([
                DKIMRisks.SignatureExpired(
                  expirationDate: Date.init(timeIntervalSince1970: 1_636_839_994))
              ])
            )
            insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Insecure)
          case _ where emailFilePath.hasSuffix("signed_idna.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMSignatureStatus.Valid
            )
            XCTAssertEqual(
              result.extractedDomainFromSenderIdnaEncoded, "xn--4ca9as.xn--brtzelein-w2a.com")
            XCTAssertEqual(result.signatures[0].info?.sdid, "xn--brtzelein-w2a.com")
            XCTAssertEqual(result.signatures[0].info?.domainSelector, "rs??3096")
            insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Valid)
          case _ where emailFilePath.hasSuffix("sha1.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Error(
                DKIMError.InvalidEntryInDKIMHeader(
                  message: "rsa-sha1 deprecated as hashing algorithm (RFC8301) ('a')")))
            error_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Error(DKIMError.OnlyInvalidSignatures))
          case _ where emailFilePath.hasSuffix("only_from.eml"):
            expected_result = DKIMVerifier.DKIMSignatureResult.init(
              status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                Set.init([
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "subject"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "date"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "to"),
                  DKIMVerifier.DKIMRisks.ImportantHeaderFieldNotSigned(name: "message-id"),
                  DKIMVerifier.DKIMRisks.SDIDNotInFrom(
                    sdid: "custom.com", fromDomain: "football.example.com"),
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
            insecure_emails += 1
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
            insecure_emails += 1
            XCTAssertEqual(result.status, DKIMStatus.Insecure)
          default:
            if result.signatures[0].info!.rsaKeySizeInBits ?? 2048 < 2048 {
              XCTAssertEqual(result.signatures[0].info!.rsaKeySizeInBits!, 1024)
              expected_result = DKIMVerifier.DKIMSignatureResult.init(
                status: DKIMVerifier.DKIMSignatureStatus.Insecure(
                  Set.init([
                    DKIMVerifier.DKIMRisks.InsecureKeySize(size: 1024, expected: 2048)
                  ])))
              insecure_emails += 1
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
    XCTAssertEqual(total_emails, 18)
    XCTAssertEqual(error_emails, 7)
    XCTAssertEqual(no_signature_emails, 2)
    XCTAssertEqual(insecure_emails, 6)
    XCTAssertEqual(valid_emails, 3)
    XCTAssertEqual(
      valid_emails + insecure_emails + error_emails + no_signature_emails, total_emails)
  }
}
