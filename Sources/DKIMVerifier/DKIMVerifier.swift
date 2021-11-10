import Crypto
import Foundation
import RegularExpressions
import _CryptoExtras

public enum DKIMError: Error, Equatable {
  // email errors
  case TagValueListParsingError(message: String)
  case RFC5322MessageParsingError(message: String)
  case InvalidRFC5322Headers(message: String)
  case NoSignature
  case OnlyInvalidSignatures

  // signature errors
  case InvalidEntryInDKIMHeader(message: String)
  case BodyHashDoesNotMatch(message: String)
  case SignatureDoesNotMatch
  case InvalidDNSEntry(message: String)
  case PublicKeyRevoked
  case PublicKeyWithIncorrectParameters  // for example keySize lower than 1024 for RSA

  // always possible
  case UnexpectedError(message: String)
}

public enum DKIMSignatureAlgorithm {
  case RSA_SHA256
  case Ed25519_SHA256
}

public enum DKIMCanonicalization {
  case Simple
  case Relaxed
}

public enum DKIMPublicKeyQueryMethod {
  case DNSTXT
}

enum DKIMTagNames: String {
  case Version = "v"  // required
  case Algorithm = "a"  // required
  case Signature = "b"  // required
  case BodyHash = "bh"  // required
  case Canonicalization = "c"  // optional
  case SDID = "d"  // required, Domain Identifier
  case SignedHeaderFields = "h"  // required
  case AUID = "i"  // optional, User Identifier
  // case BodyLength = "l"  // optional, ignored for BodyHash calculation because security risk
  case PublicKeyQueryMethod = "q"  // optional, only dns/txt
  case DomainSelector = "s"  // required
  case SignatureTimestamp = "t"  // optional
  case SignatureExpiration = "x"  // optional
  case CopiedHeaderFields = "z"  // optional
}

enum DNSEntryTagNames: String {
  case Version = "v"  // optional
  case AcceptableHashAlgorithms = "h"  // optional
  case KeyType = "k"  // optional
  case Notes = "n"  // optional
  case PublicKey = "p"  // required
  case ServiceType = "s"  // optional
  case Flags = "t"  // optional
}

public enum DKIMSignatureStatus: Equatable {
  case Valid
  case Insecure(Set<DKIMRisks>)
  case Error(DKIMError)
}

public enum DKIMStatus: Equatable {
  case Valid
  case Insecure
  case Error(DKIMError)
}

public enum DKIMRisks: Hashable, Equatable {
  case SDIDNotInFrom(sdid: String, fromDomain: String)  // third-party signature, DKIM Domain not a subdomain or equal to From: Sender
  case ImportantHeaderFieldNotSigned(name: String)  // only From: field required, but more fields are better else manipulation possible
  // Subject, Content-Type, Reply-To,... should be signed
  case InsecureKeySize(size: Int, expected: Int)  // using a key size less than 2048 for RSA

  // Not accepted as a risk anymore (high risk, not used)
  //   -> Ignored in body hash validation, error on additional content
  // case UsingLengthParameter  // only verified to a specific body length

  // Not accepted as a risk anymore (RFC8301) -> Error
  // case UsingSHA1  // insecure hashing algorithm
}

var LowestSecureKeySize: Int = 2048

// The rfc6376 recommended header fields to sign
let importantHeaderFields: Set<String> = [
  "from", "sender", "reply-to", "subject", "date", "message-id", "to", "cc",
  "mime-version", "content-type", "content-transfer-encoding",
  "content-id", "content-description", "resent-date", "resent-from",
  "resent-sender", "resent-to", "resent-cc", "resent-message-id",
  "in-reply-to", "references", "list-id", "list-help", "list-unsubscribe",
  "list-subscribe", "list-post", "list-owner", "list-archive",
]

public struct DKIMSignatureInfo: Equatable {
  public var version: UInt
  public var algorithm: DKIMSignatureAlgorithm
  public var signature: String
  public var bodyHash: String
  public var headerCanonicalization: DKIMCanonicalization  // optional, but default simple
  public var bodyCanonicalization: DKIMCanonicalization  // optional, but default simple
  public var sdid: String
  public var signedHeaderFields: [String]
  public var domainSelector: String
  public var publicKeyQueryMethod: DKIMPublicKeyQueryMethod  // optional, but default dns/txt

  public var auid: String?
  // public var bodyLength: UInt?
  public var signatureTimestamp: Date?
  public var signatureExpiration: String?
  public var copiedHeaderFields: String?

  public var rsaKeySizeInBits: Int?
}

public struct DKIMSignatureResult: Equatable {
  public var status: DKIMSignatureStatus
  public var info: DKIMSignatureInfo?
}

public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var signatures: [DKIMSignatureResult]
  public var emailFromSender: String?
  public var extractedDomainFromSender: String?
  public var DMARCResult: DMARCResult?

  init() {
    status = DKIMStatus.Error(DKIMError.UnexpectedError(message: "initial status"))
    signatures = []
    emailFromSender = nil
    extractedDomainFromSender = nil
  }

  init(status: DKIMStatus) {
    self.status = status
    signatures = []
    emailFromSender = nil
    extractedDomainFromSender = nil
  }
}

func validateDKIMFields(
  email_headers: OrderedKeyValueArray, email_body: String, dkimFields: TagValueDictionary,
  dkim_result: inout DKIMSignatureResult, extractedDomainFromSender: String
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
      #"\s+"#, replacer: { num, m in "" })
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

  if !(extractedDomainFromSender == sdid) && !extractedDomainFromSender.hasSuffix(".\(sdid)") {
    risks.insert(DKIMRisks.SDIDNotInFrom(sdid: sdid, fromDomain: extractedDomainFromSender))
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
    bodyCanonicalization: canonicalizationBodyMethod, sdid: sdid,
    signedHeaderFields: signedHeaderFields, domainSelector: domainSelectorString,
    publicKeyQueryMethod: dkimPublicQueryMethod, auid: nil,
    signatureTimestamp: nil, signatureExpiration: nil, copiedHeaderFields: nil)

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
  }

  if dkimFields[DKIMTagNames.SignatureExpiration.rawValue] != nil {
    guard
      let signatureExpirationNumber = UInt(dkimFields[DKIMTagNames.SignatureExpiration.rawValue]!)
    else {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "signature expiration not a number")
    }
    let signatureExpiration = Date(timeIntervalSince1970: Double(signatureExpirationNumber))
    info.signatureTimestamp = signatureExpiration
  }

  dkim_result.info = info

  return risks
}

public func verifyDKIMSignatures(
  dnsLoopupTxtFunction: @escaping (String) throws -> String?, email_raw: String,
  verifyDMARC: Bool = false
)
  -> DKIMResult
{
  var result: DKIMResult = DKIMResult.init()

  // seperate headers from body
  var (headers, body): (OrderedKeyValueArray, String)
  do {
    (headers, body) = try parseRFC822Message(message: email_raw)
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  guard !headers.isEmpty else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC5322Headers(message: "invalid email without header"))
    return result
  }

  guard headers.contains(where: { $0.key.lowercased() == "from" }) else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC5322Headers(message: "no from email header"))
    return result
  }

  guard headers.filter({ $0.key.lowercased() == "from" }).count == 1 else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC5322Headers(message: "multiple from email headers"))
    return result
  }

  let from_header_field: String = headers.last(where: { $0.key.lowercased() == "from" }
  )!.value

  result.emailFromSender = from_header_field.trimmingCharacters(in: .whitespacesAndNewlines)

  result.extractedDomainFromSender = parseDomainFromEmail(
    email: parseEmailFromField(raw_from_field: result.emailFromSender!) ?? "")

  guard result.extractedDomainFromSender != nil else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC5322Headers(
        message: "could not extract domain out of email From: field \(result.emailFromSender!)"))
    return result
  }

  guard headers.contains(where: { $0.key.lowercased() == "dkim-signature" }) else {
    result.status = DKIMStatus.Error(DKIMError.NoSignature)
    return result
  }

  for (index, header) in headers.enumerated() {
    if header.key.lowercased() != "dkim-signature" {
      continue
    }

    do {
      let signatureResult = try verifyDKIMSignature(
        dnsLoopupTxtFunction: dnsLoopupTxtFunction,
        emailHeaders: headers, emailBody: body, dkimHeaderFieldIndex: index,
        extractedDomainFromSender: result.extractedDomainFromSender!)
      result.signatures.append(signatureResult)
    } catch let error as DKIMError {
      result.status = DKIMStatus.Error(error)
      return result
    } catch {
      result.status = DKIMStatus.Error(
        DKIMError.UnexpectedError(message: error.localizedDescription))
      return result
    }
  }

  if verifyDMARC {
    var validDKIMDomains: [String] = []
    for signature in result.signatures {
      if signature.status == .Valid {
        validDKIMDomains.append(signature.info!.sdid)
      }
      if case .Insecure = signature.status {
        validDKIMDomains.append(signature.info!.sdid)
      }
    }

    do {
      result.DMARCResult = try checkDMARC(
        dnsLookupTxtFunction: dnsLoopupTxtFunction,
        fromSenderDomain: result.extractedDomainFromSender!, validDKIMDomains: validDKIMDomains)
    } catch {
      result.status = DKIMStatus.Error(
        DKIMError.UnexpectedError(message: error.localizedDescription))
      return result
    }
  }

  if result.signatures.contains(where: { $0.status == DKIMSignatureStatus.Valid }) {
    result.status = DKIMStatus.Valid
  } else if result.signatures.contains(where: {
    if case .Insecure = $0.status { return true } else { return false }
  }) {
    result.status = DKIMStatus.Insecure
  } else {
    result.status = DKIMStatus.Error(DKIMError.OnlyInvalidSignatures)
  }

  return result
}

func verifyDKIMSignature(
  dnsLoopupTxtFunction: @escaping (String) throws -> String?,
  emailHeaders: OrderedKeyValueArray, emailBody: String, dkimHeaderFieldIndex: Int,
  extractedDomainFromSender: String
) throws -> DKIMSignatureResult {
  var result: DKIMSignatureResult = DKIMSignatureResult.init(
    status: DKIMSignatureStatus.Error(DKIMError.UnexpectedError(message: "unset error")), info: nil)
  var risks: Set<DKIMRisks> = Set<DKIMRisks>.init()

  let dkimFields = try parseTagValueList(raw_list: emailHeaders[dkimHeaderFieldIndex].value)

  // validate dkim fields and add possible risks
  do {
    risks = risks.union(
      try validateDKIMFields(
        email_headers: emailHeaders, email_body: emailBody, dkimFields: dkimFields,
        dkim_result: &result, extractedDomainFromSender: extractedDomainFromSender))
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  guard let parameters = result.info else {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: "validation did not parse parameters"))
    return result
  }

  let canonEmailHeaders: OrderedKeyValueArray
  let canonEmailBody: String
  do {
    switch parameters.headerCanonicalization {
    case DKIMCanonicalization.Simple:
      canonEmailHeaders = try SimpleCanonicalizationHeaderAlgorithm.canonicalize(
        headers: emailHeaders)
    case DKIMCanonicalization.Relaxed:
      canonEmailHeaders = try RelaxedCanonicalizationHeaderAlgorithm.canonicalize(
        headers: emailHeaders)
    }

    switch parameters.bodyCanonicalization {
    case DKIMCanonicalization.Simple:
      canonEmailBody = try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: emailBody)
    case DKIMCanonicalization.Relaxed:
      canonEmailBody = try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: emailBody)
    }
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  // check if the calculated body hash matches the deposited body hash in the DKIM Header
  let provided_hash = parameters.bodyHash

  let calculated_hash: String
  switch parameters.algorithm {
  case DKIMSignatureAlgorithm.RSA_SHA256, DKIMSignatureAlgorithm.Ed25519_SHA256:
    calculated_hash = Data(Crypto.SHA256.hash(data: canonEmailBody.data(using: .utf8)!))
      .base64EncodedString()
  }

  guard provided_hash == calculated_hash else {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.BodyHashDoesNotMatch(
        message: "provided hash " + provided_hash + " not equal to calculated hash "
          + calculated_hash))
    return result
  }

  // use the defined selector and domain from the DKIM header to query the DNS public key entry
  let domain = parameters.domainSelector + "._domainkey." + parameters.sdid

  // use the provided dns loopkup function
  let record: String
  do {
    let tempRecord = try dnsLoopupTxtFunction(domain)
    guard tempRecord != nil else {
      result.status = DKIMSignatureStatus.Error(
        DKIMError.InvalidDNSEntry(message: "DNS Entry is empty for domain: \(domain)"))
      return result
    }
    record = tempRecord!
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  let dns_tag_value_list: TagValueDictionary
  do {
    dns_tag_value_list = try parseTagValueList(raw_list: record)
  } catch let error as DKIMError
    where error == .TagValueListParsingError(message: "no value for key: p")
  {
    result.status = DKIMSignatureStatus.Error(DKIMError.PublicKeyRevoked)
    return result
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }
  guard let public_key_base64 = dns_tag_value_list[DNSEntryTagNames.PublicKey.rawValue] else {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.InvalidDNSEntry(message: "no public key dns entry (p)"))
    return result
  }

  // print(Optional(public_key_base64))

  //    guard let dns_encryption_type = dns_tag_value_list[DNSEntryTagNames.KeyType.rawValue] else {
  //      throw DKIMError.invalidDNSEntry(message: "no k entry")
  //    }
  //
  //    switch encryption_method {
  //    case DKIMEncryption.Ed25519_SHA256:
  //      guard dns_encryption_type == "ed25519" else {
  //        throw DKIMError.invalidDNSEntry(message: "email encryption different from dns encryption")
  //      }
  //    case DKIMEncryption.RSA_SHA256:
  //      guard dns_encryption_type == "rsa" else {
  //        throw DKIMError.invalidDNSEntry(message: "email encryption different from dns encryption")
  //      }
  //    }

  guard let public_key_data = Data(base64Encoded: public_key_base64)
  else {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.InvalidDNSEntry(message: "invalid base64 encoding for public key"))
    return result
  }

  let raw_signed_string: String

  // generate the signed data from the headers without the signature
  do {
    raw_signed_string = try DKIMVerifier.generateSignedData(
      dkimHeaderField: canonEmailHeaders[dkimHeaderFieldIndex],
      headers: canonEmailHeaders, includeHeaders: parameters.signedHeaderFields)
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  guard let raw_signed_data = raw_signed_string.data(using: .utf8) else {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.InvalidEntryInDKIMHeader(message: "could not encode using utf8"))
    return result

  }

  guard let dkim_signature_data = Data(base64Encoded: parameters.signature) else {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.InvalidEntryInDKIMHeader(message: "invalid base64 in signature ('b') entry"))
    return result
  }

  let signature_result: Bool
  do {
    switch parameters.algorithm {

    case DKIMSignatureAlgorithm.RSA_SHA256:
      let keySizeInBits: Int
      (keySizeInBits, signature_result) = try DKIMVerifier.checkRSA_SHA256_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)

      result.info?.rsaKeySizeInBits = keySizeInBits

      if keySizeInBits < LowestSecureKeySize {
        risks.insert(DKIMRisks.InsecureKeySize(size: keySizeInBits, expected: LowestSecureKeySize))
      }

    case DKIMSignatureAlgorithm.Ed25519_SHA256:
      signature_result = try DKIMVerifier.checkEd25519_SHA256_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
    }
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch CryptoKitError.incorrectParameterSize {
    result.status = DKIMSignatureStatus.Error(DKIMError.PublicKeyWithIncorrectParameters)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: "CryptoKit: \(error)"))
    return result
  }

  if signature_result {
    if risks.count > 0 {
      result.status = DKIMSignatureStatus.Insecure(risks)
    } else {
      result.status = DKIMSignatureStatus.Valid
    }
  } else {
    result.status = DKIMSignatureStatus.Error(DKIMError.SignatureDoesNotMatch)
  }

  return result
}
