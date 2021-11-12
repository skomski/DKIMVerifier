import Foundation
import RegularExpressions

func validateDKIMFields(
  email_headers: OrderedKeyValueArray, email_body: String, dkimFields: TagValueDictionary,
  dkim_result: inout DKIMSignatureResult, extractedDomainFromSenderIdnaEncoded: String
) throws -> Set<DKIMRisks> {
  var risks: Set<DKIMRisks> = Set<DKIMRisks>.init()

  guard let dkimVersionString: String = dkimFields[DKIMTagNames.Version.rawValue] else {
    throw DKIMError.InvalidEntryInDKIMHeader(message: "no version provided ('v')")
  }

  guard let dkimVersion: UInt = UInt(dkimVersionString) else {
    throw DKIMError.InvalidEntryInDKIMHeader(message: "invalid version provided ('v')")
  }

  guard dkimVersion == 1 else {
    throw DKIMError.InvalidEntryInDKIMHeader(
      message: "invalid version \(dkimVersion) != 1 provided ('v')")
  }

  guard let dkimSignature = dkimFields[DKIMTagNames.Signature.rawValue] else {
    throw DKIMError.InvalidEntryInDKIMHeader(message: "no b entry")
  }

  let dkimSignatureClean: String
  do {
    // remove whitespace from signature
    dkimSignatureClean = try dkimSignature.regexSub(
      #"\s+"#, replacer: { _, _ in "" })
  } catch {
    throw DKIMError.UnexpectedError(message: error.localizedDescription)
  }

  guard Data(base64Encoded: dkimSignatureClean) != nil else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "invalid base64 in signature ('b') entry")
  }

  // check if the calculated body hash matches the deposited body hash in the DKIM Header
  guard let bodyHash = dkimFields[DKIMTagNames.BodyHash.rawValue] else {
    throw DKIMError.InvalidEntryInDKIMHeader(message: "no body hash provided ('bh')")
  }

  guard Data(base64Encoded: bodyHash) != nil else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "invalid base64 in body hash ('bh') entry")
  }

  let dkimSignatureAlgorithm: DKIMSignatureAlgorithm
  let dkimSignatureAlgorithmString: String? = dkimFields[DKIMTagNames.Algorithm.rawValue]
  if dkimSignatureAlgorithmString == "rsa-sha256" {
    dkimSignatureAlgorithm = DKIMSignatureAlgorithm.RSA_SHA256
  } else if dkimSignatureAlgorithmString == "ed25519-sha256" {
    dkimSignatureAlgorithm = DKIMSignatureAlgorithm.Ed25519_SHA256
  } else if dkimSignatureAlgorithmString == "rsa-sha1" {
    throw DKIMError.InvalidEntryInDKIMHeader(
      message: "rsa-sha1 deprecated as hashing algorithm (RFC8301) ('a')")
  } else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(
        message:
          "invalid signature algorithm provided \(dkimSignatureAlgorithmString ?? "none") ('a') (rsa-sha256 and ed25519-sha256 supported"
      )

  }

  let canonicalizationHeaderMethod: DKIMCanonicalization
  let canonicalizationBodyMethod: DKIMCanonicalization

  let canonicalizationValueString = dkimFields[DKIMTagNames.Canonicalization.rawValue]

  switch canonicalizationValueString {
  case "relaxed":
    canonicalizationHeaderMethod = DKIMCanonicalization.Relaxed
    canonicalizationBodyMethod = DKIMCanonicalization.Simple
  case "relaxed/relaxed":
    canonicalizationHeaderMethod = DKIMCanonicalization.Relaxed
    canonicalizationBodyMethod = DKIMCanonicalization.Relaxed
  case "simple/relaxed":
    canonicalizationHeaderMethod = DKIMCanonicalization.Simple
    canonicalizationBodyMethod = DKIMCanonicalization.Relaxed
  case "relaxed/simple":
    canonicalizationHeaderMethod = DKIMCanonicalization.Relaxed
    canonicalizationBodyMethod = DKIMCanonicalization.Simple
  case nil, "simple/simple":
    canonicalizationHeaderMethod = DKIMCanonicalization.Simple
    canonicalizationBodyMethod = DKIMCanonicalization.Simple
  default:
    throw
      DKIMError.InvalidEntryInDKIMHeader(
        message:
          "invalid canonicalization value \(canonicalizationValueString!) provided ('c')")
  }

  guard let signedHeaderFieldsString = dkimFields[DKIMTagNames.SignedHeaderFields.rawValue] else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "missing required signed header field (h)")
  }

  let signedHeaderFields: [String]
  do {
    signedHeaderFields =
      try signedHeaderFieldsString
      .regexSplit(#"\s*:\s*"#).map({
        $0.lowercased()
      })
  } catch let error as DKIMError {
    throw error
  } catch {
    throw DKIMError.UnexpectedError(message: error.localizedDescription)
  }

  guard signedHeaderFields.contains("from") else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "signed header fields missing from: field (h)")
  }

  for importantHeaderField in importantHeaderFields {
    if email_headers.contains(where: { $0.key.lowercased() == importantHeaderField })
      && !signedHeaderFields.contains(importantHeaderField)
    {
      risks.insert(DKIMRisks.ImportantHeaderFieldNotSigned(name: importantHeaderField))
    }
  }

  guard let domainSelectorString = dkimFields[DKIMTagNames.DomainSelector.rawValue] else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "missing required domain selector field (d)")
  }

  guard let sdid = dkimFields[DKIMTagNames.SDID.rawValue]?.lowercased() else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "missing required sdid field (s)")
  }

  guard let sdidIdnaEncoded = sdid.idnaEncoded else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "could not encoded sdid field to idna (s)")
  }

  if !(extractedDomainFromSenderIdnaEncoded == sdidIdnaEncoded)
    && !extractedDomainFromSenderIdnaEncoded.hasSuffix(".\(sdidIdnaEncoded)")
  {
    risks.insert(
      DKIMRisks.SDIDNotInFrom(
        sdid: sdidIdnaEncoded, fromDomain: extractedDomainFromSenderIdnaEncoded))
  }

  let dkimPublicQueryMethod: DKIMPublicKeyQueryMethod = DKIMPublicKeyQueryMethod.DNSTXT

  if dkimFields[DKIMTagNames.PublicKeyQueryMethod.rawValue] != nil {
    guard dkimFields[DKIMTagNames.PublicKeyQueryMethod.rawValue]! == "dns/txt" else {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "public key query method != dns/txt ('p')")
    }
  }

  var info: DKIMSignatureInfo = DKIMSignatureInfo.init(
    version: dkimVersion, algorithm: dkimSignatureAlgorithm, signature: dkimSignatureClean,
    bodyHash: bodyHash, headerCanonicalization: canonicalizationHeaderMethod,
    bodyCanonicalization: canonicalizationBodyMethod, sdid: sdidIdnaEncoded,
    signedHeaderFields: signedHeaderFields, domainSelector: domainSelectorString,
    publicKeyQueryMethod: dkimPublicQueryMethod, auid: nil,
    signatureTimestamp: nil, signatureExpiration: nil)

  if dkimFields[DKIMTagNames.AUID.rawValue] != nil {
    let auid = dkimFields[DKIMTagNames.AUID.rawValue]!
    info.auid = auid
  } else {
    info.auid = "@\(info.sdid)"
  }

  if dkimFields[DKIMTagNames.SignatureTimestamp.rawValue] != nil {
    guard let signatureTimestampNumber = UInt(dkimFields[DKIMTagNames.SignatureTimestamp.rawValue]!)
    else {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "signature timestamp not a number")
    }
    let signatureTimestamp = Date(timeIntervalSince1970: Double(signatureTimestampNumber))
    info.signatureTimestamp = signatureTimestamp

    if signatureTimestamp > Date() {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "signature timestamp is in the future")
    }
  }

  if dkimFields[DKIMTagNames.SignatureExpiration.rawValue] != nil {
    guard
      let signatureExpirationNumber = UInt(dkimFields[DKIMTagNames.SignatureExpiration.rawValue]!)
    else {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "signature expiration not a number")
    }
    let signatureExpiration = Date(timeIntervalSince1970: Double(signatureExpirationNumber))
    info.signatureExpiration = signatureExpiration

    if signatureExpiration < Date() {
      risks.insert(DKIMRisks.SignatureExpired(expirationDate: signatureExpiration))
    }
  }

  dkim_result.info = info

  return risks
}
