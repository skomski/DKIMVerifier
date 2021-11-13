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
  if dkimSignatureAlgorithmString == DKIMSignatureAlgorithm.RSA_SHA256.rawValue {
    dkimSignatureAlgorithm = DKIMSignatureAlgorithm.RSA_SHA256
  } else if dkimSignatureAlgorithmString == DKIMSignatureAlgorithm.Ed25519_SHA256.rawValue {
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

  guard let signedHeaderFields = parseColonSeperatedList(rawList: signedHeaderFieldsString) else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "could not parse signed header field (h)")
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

  let finalAuid: String
  if dkimFields[DKIMTagNames.AUID.rawValue] != nil {
    let auid = dkimFields[DKIMTagNames.AUID.rawValue]!
    finalAuid = auid
  } else {
    finalAuid = "@\(sdid)"
  }

  var info: DKIMSignatureInfo = DKIMSignatureInfo.init(
    version: dkimVersion, algorithm: dkimSignatureAlgorithm, signature: dkimSignatureClean,
    bodyHash: bodyHash, headerCanonicalization: canonicalizationHeaderMethod,
    bodyCanonicalization: canonicalizationBodyMethod, sdid: sdidIdnaEncoded,
    signedHeaderFields: signedHeaderFields, domainSelector: domainSelectorString,
    publicKeyQueryMethod: dkimPublicQueryMethod, auid: finalAuid,
    signatureTimestamp: nil, signatureExpiration: nil)

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

func validateDKIMSignatureDNSFields(
  dkimResult: inout DKIMSignatureResult,
  dnsFields: TagValueDictionary,
  extractedDomainFromSenderIdnaEncoded: String
) throws -> Set<DKIMRisks> {
  let risks: Set<DKIMRisks> = Set<DKIMRisks>.init()

  guard let publicKey = dnsFields[DNSEntryTagNames.PublicKey.rawValue] else {
    throw DKIMError.InvalidDNSEntry(message: "required: no public key dns entry (p)")
  }

  dkimResult.dnsInfo = DKIMSignatureDNSInfo.init(
    publicKey: publicKey, version: nil, acceptableHashAlgorithms: nil, keyType: nil, notes: nil,
    serviceType: nil, flags: nil)

  if dnsFields[DNSEntryTagNames.Version.rawValue] != nil {
    let version = dnsFields[DNSEntryTagNames.Version.rawValue]!
    guard version == "DKIM1" else {
      throw DKIMError.InvalidDNSEntry(
        message: "invalid version in dns entry DKIM1 != \"\(version)\" (v)")
    }
  }

  if dnsFields[DNSEntryTagNames.AcceptableHashAlgorithms.rawValue] != nil {
    let acceptableHashAlgorithms = dnsFields[DNSEntryTagNames.AcceptableHashAlgorithms.rawValue]!
    guard let parsedList = parseColonSeperatedList(rawList: acceptableHashAlgorithms) else {
      throw DKIMError.InvalidDNSEntry(
        message: "could not parse dns entry acceptableHashAlgorithms (h)")
    }
    switch dkimResult.info!.algorithm {
    case DKIMSignatureAlgorithm.Ed25519_SHA256, DKIMSignatureAlgorithm.RSA_SHA256:
      guard parsedList.contains(DKIMHashAlgorithm.SHA256.rawValue) else {
        throw DKIMError.InvalidDNSEntry(
          message:
            "dns entry acceptableHashAlgorithms does not contain \(DKIMHashAlgorithm.SHA256.rawValue) (h)"
        )
      }
    }
  }

  if dnsFields[DNSEntryTagNames.KeyType.rawValue] != nil {
    let keyType = dnsFields[DNSEntryTagNames.KeyType.rawValue]!
    let error_message =
      "dns entry keyType \(keyType) is not expected from DKIMSignature algorithm \(dkimResult.info!.algorithm.rawValue) (h)"
    switch keyType {
    case "rsa":
      guard dkimResult.info?.algorithm == DKIMSignatureAlgorithm.RSA_SHA256 else {
        throw DKIMError.InvalidDNSEntry(message: error_message)
      }
      dkimResult.dnsInfo!.keyType = DKIMKeyType.RSA
    case "ed25519":
      guard dkimResult.info?.algorithm == DKIMSignatureAlgorithm.Ed25519_SHA256 else {
        throw DKIMError.InvalidDNSEntry(message: error_message)
      }
      dkimResult.dnsInfo!.keyType = DKIMKeyType.Ed25519
    default:
      throw DKIMError.InvalidDNSEntry(message: error_message)
    }
  }

  if dnsFields[DNSEntryTagNames.Notes.rawValue] != nil {
    let notes = dnsFields[DNSEntryTagNames.Notes.rawValue]!
    dkimResult.dnsInfo!.notes = notes
  }

  if dnsFields[DNSEntryTagNames.ServiceType.rawValue] != nil {
    let serviceType = dnsFields[DNSEntryTagNames.ServiceType.rawValue]!
    guard let parsedList = parseColonSeperatedList(rawList: serviceType) else {
      throw DKIMError.InvalidDNSEntry(message: "could not parse dns entry service type (s)")
    }
    var serviceTypeList: [DKIMServiceType] = []
    for serviceString in parsedList {
      switch serviceString {
      case DKIMServiceType.Email.rawValue:
        serviceTypeList.append(DKIMServiceType.Email)
      default:
        throw DKIMError.InvalidDNSEntry(message: "unrecognized service type in dns entry (s)")
      }
    }
    dkimResult.dnsInfo!.serviceType = serviceTypeList
  } else {
    dkimResult.dnsInfo!.serviceType = [DKIMServiceType.All]
  }

  if dnsFields[DNSEntryTagNames.Flags.rawValue] != nil {
    let unparsedList = dnsFields[DNSEntryTagNames.Flags.rawValue]!
    guard let parsedList = parseColonSeperatedList(rawList: unparsedList) else {
      throw DKIMError.InvalidDNSEntry(message: "could not parse dns entry flags (t)")
    }

    var flags: [DKIMSignatureDNSFlag] = []
    for flagString in parsedList {
      switch flagString {
      case DKIMSignatureDNSFlag.TestMode.rawValue:
        flags.append(DKIMSignatureDNSFlag.TestMode)
      case DKIMSignatureDNSFlag.AUIDDomainPartMustBeEqualToSDID.rawValue:
        flags.append(DKIMSignatureDNSFlag.AUIDDomainPartMustBeEqualToSDID)
      default:
        throw DKIMError.InvalidDNSEntry(message: "unrecognized flag in dns entry (t)")
      }
    }
    dkimResult.dnsInfo!.flags = flags

    if dkimResult.dnsInfo!.flags!.contains(DKIMSignatureDNSFlag.TestMode) {
      throw DKIMError.DKIMTestMode
    }

    if dkimResult.dnsInfo!.flags!.contains(DKIMSignatureDNSFlag.AUIDDomainPartMustBeEqualToSDID) {
      let getDomainAuid = dkimResult.info!.auid.split(separator: "@")

      if (getDomainAuid.count == 2 && dkimResult.info!.sdid != getDomainAuid[1].idnaEncoded!)
        || (getDomainAuid.count == 1 && dkimResult.info!.sdid != getDomainAuid[0].idnaEncoded!)
      {
        throw DKIMError.AUIDDomainPartMustBeEqualToSDIDValidationError
      }
    }
  }

  return risks
}
