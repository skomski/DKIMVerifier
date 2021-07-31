import Crypto
import Foundation
import RegularExpressions
import _CryptoExtras

public enum DKIMError: Error, Equatable {
  case TagValueListParsingError(message: String)
  case RFC822MessageParsingError(message: String)
  case InvalidRFC822Headers(message: String)
  case InvalidEntryInDKIMHeader(message: String)
  case BodyHashDoesNotMatch(message: String)
  case SignatureDoesNotMatch
  case InvalidDNSEntry(message: String)
  case UnexpectedError(message: String)
}

enum DKIMSignatureAlgorithm {
  case RSA_SHA1
  case RSA_SHA256
  case Ed25519_SHA256
}

enum DKIMCanonicalization {
  case Simple
  case Relaxed
}

enum DKIMPublicKeyQueryMethod {
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
  case BodyLength = "l"  // optional, Security Risk
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

public enum DKIMStatus: Equatable {
  case Valid
  case Valid_Insecure(Set<DKIMRisks>)
  case Invalid(DKIMError)
  case NoSignature
  case Error(DKIMError)
}

public enum DKIMRisks: Hashable, Equatable {
  case UsingLengthParameter  // only verified to a specific body length
  case UsingSHA1  // insecure hashing algorithm
  case SDIDNotEqualToSender  // third-party signature, From: Sender different to DKIM Domain
  case ImportantHeaderFieldNotSigned(name: String)  // only From: field required, but more fields are better else manipulation possible
  // Subject, Content-Type, Reply-To,... should be signed
}

// The rfc6376 recommended header fields to sign
let importantHeaderFields: Set<String> = [
  "from", "sender", "reply-to", "subject", "date", "message-id", "to", "cc",
  "mime-version", "content-type", "content-transfer-encoding",
  "content-id", "content-description", "resent-date", "resent-from",
  "resent-sender", "resent-to", "resent-cc", "resent-message-id",
  "in-reply-to", "references", "list-id", "list-help", "list-unsubscribe",
  "list-subscribe", "list-post", "list-owner", "list-archive",
]

public struct DKIMInfo: Equatable {
  var version: UInt
  var algorithm: DKIMSignatureAlgorithm
  var signature: String
  var bodyHash: String
  var headerCanonicalization: DKIMCanonicalization  // optional, but default simple
  var bodyCanonicalization: DKIMCanonicalization  // optional, but default simple
  var sdid: String
  var signedHeaderFields: [String]
  var domainSelector: String
  var publicKeyQueryMethod: DKIMPublicKeyQueryMethod  // optional, but default dns/txt

  var auid: String?
  var bodyLength: UInt?
  var signatureTimestamp: Date?
  var signatureExpiration: String?
  var copiedHeaderFields: String?
}

public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var info: DKIMInfo?
  public var email_from_sender: String?

  init() {
    status = DKIMStatus.Error(DKIMError.UnexpectedError(message: "initial status"))
    info = nil
    email_from_sender = nil
  }

  init(status: DKIMStatus) {
    self.status = status
    info = nil
    email_from_sender = nil
  }
}

var dnsLoopupTxtFunction: (String) -> String? = { (domainName) in "fail" }

func validate_dkim_fields(
  email_headers: OrderedKeyValueArray, email_body: String, dkimFields: TagValueDictionary,
  dkim_result: inout DKIMResult
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
    dkimSignatureAlgorithm = DKIMSignatureAlgorithm.RSA_SHA1
    risks.insert(DKIMRisks.UsingSHA1)
  } else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(
        message:
          "invalid signature algorithm provided \(dkimSignatureAlgorithmString ?? "none") ('a') (rsa-sha256, ed25519-sha256, rsa-sha1 supported"
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

  guard let sdid = dkimFields[DKIMTagNames.SDID.rawValue] else {
    throw
      DKIMError.InvalidEntryInDKIMHeader(message: "missing required sdid field (s)")
  }

  let dkimPublicQueryMethod: DKIMPublicKeyQueryMethod = DKIMPublicKeyQueryMethod.DNSTXT

  if dkimFields[DKIMTagNames.PublicKeyQueryMethod.rawValue] != nil {
    guard dkimFields[DKIMTagNames.PublicKeyQueryMethod.rawValue]! == "dns/txt" else {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "public key query method != dns/txt ('p')")
    }
  }

  var info: DKIMInfo = DKIMInfo.init(
    version: dkimVersion, algorithm: dkimSignatureAlgorithm, signature: dkimSignatureClean,
    bodyHash: bodyHash, headerCanonicalization: canonicalizationHeaderMethod,
    bodyCanonicalization: canonicalizationBodyMethod, sdid: sdid,
    signedHeaderFields: signedHeaderFields, domainSelector: domainSelectorString,
    publicKeyQueryMethod: dkimPublicQueryMethod, auid: nil, bodyLength: nil,
    signatureTimestamp: nil, signatureExpiration: nil, copiedHeaderFields: nil)

  if dkimFields[DKIMTagNames.BodyLength.rawValue] != nil {
    risks.insert(DKIMRisks.UsingLengthParameter)

    guard let bodyLength = UInt(dkimFields[DKIMTagNames.BodyLength.rawValue]!) else {
      throw DKIMError.InvalidEntryInDKIMHeader(message: "body length not a number")
    }

    info.bodyLength = bodyLength
  }

  if dkimFields[DKIMTagNames.AUID.rawValue] != nil {
    let auid = dkimFields[DKIMTagNames.AUID.rawValue]!
    info.auid = auid
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

public func verify(dnsLoopupTxtFunction: @escaping (String) throws -> String?, email_raw: String)
  -> DKIMResult
{
  var result: DKIMResult = DKIMResult.init()
  var risks: Set<DKIMRisks> = Set<DKIMRisks>.init()

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
      DKIMError.InvalidRFC822Headers(message: "invalid email without header"))
    return result
  }

  guard headers.contains(where: { $0.key.lowercased() == "from" }) else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC822Headers(message: "no from email header"))
    return result
  }

  let from_header_field: String = headers.last(where: { $0.key.lowercased() == "from" }
  )!.value

  result.email_from_sender = from_header_field.trimmingCharacters(in: .whitespacesAndNewlines)

  guard headers.contains(where: { $0.key.lowercased() == "dkim-signature" }) else {
    result.status = DKIMStatus.NoSignature
    return result
  }

  // TODO: multiple dkim signatures, validate in order
  let dkim_header_field: String = headers.last(where: { $0.key.lowercased() == "dkim-signature" }
  )!.value
  let tag_value_list: TagValueDictionary
  do {
    tag_value_list = try parseTagValueList(raw_list: dkim_header_field)
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  // validate dkim fields and add possible risks
  do {
    risks = risks.union(
      try validate_dkim_fields(
        email_headers: headers, email_body: body, dkimFields: tag_value_list, dkim_result: &result))
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  guard let parameters = result.info else {
    result.status = DKIMStatus.Error(
      DKIMError.UnexpectedError(message: "validation did not parse parameters"))
    return result
  }

  do {
    switch parameters.headerCanonicalization {
    case DKIMCanonicalization.Simple:
      headers = try SimpleCanonicalizationHeaderAlgorithm.canonicalize(headers: headers)
    case DKIMCanonicalization.Relaxed:
      headers = try RelaxedCanonicalizationHeaderAlgorithm.canonicalize(headers: headers)
    }

    switch parameters.bodyCanonicalization {
    case DKIMCanonicalization.Simple:
      body = try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: body)
    case DKIMCanonicalization.Relaxed:
      body = try RelaxedCanonicalizationBodyAlgorithm.canonicalize(body: body)
    }
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  //  if parameters.bodyLength != nil {
  //    guard parameters.bodyLength! <= body.count else {
  //      result.status = DKIMStatus.Error(
  //        DKIMError.InvalidEntryInDKIMHeader(
  //          message:
  //            "supplied body length \(parameters.bodyLength!) > email body length \(body.count)"))
  //      return result
  //    }
  //  }

  // check if the calculated body hash matches the deposited body hash in the DKIM Header
  let provided_hash = parameters.bodyHash
  //print(Optional(body))
  let calculated_hash: String
  switch parameters.algorithm {
  case DKIMSignatureAlgorithm.RSA_SHA1:
    calculated_hash = Data(Crypto.Insecure.SHA1.hash(data: body.data(using: .utf8)!))
      .base64EncodedString()
  case DKIMSignatureAlgorithm.RSA_SHA256, DKIMSignatureAlgorithm.Ed25519_SHA256:
    calculated_hash = Data(Crypto.SHA256.hash(data: body.data(using: .utf8)!))
      .base64EncodedString()
  }

  guard provided_hash == calculated_hash else {
    result.status = DKIMStatus.Invalid(
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
      result.status = DKIMStatus.Error(
        DKIMError.InvalidDNSEntry(message: "DNS Entry is empty for domain: \(domain)"))
      return result
    }
    record = tempRecord!
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  let dns_tag_value_list: TagValueDictionary
  do {
    dns_tag_value_list = try parseTagValueList(raw_list: record)
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }
  guard let public_key_base64 = dns_tag_value_list[DNSEntryTagNames.PublicKey.rawValue] else {
    result.status = DKIMStatus.Error(
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
    result.status = DKIMStatus.Error(
      DKIMError.InvalidDNSEntry(message: "invalid base64 encoding for public key"))
    return result
  }

  let raw_signed_string: String

  // generate the signed data from the headers without the signature
  do {
    raw_signed_string = try DKIMVerifier.generateSignedData(
      headers: headers, includeHeaders: parameters.signedHeaderFields)
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  // print(Optional(raw_signed_string))

  guard let raw_signed_data = raw_signed_string.data(using: .utf8) else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidEntryInDKIMHeader(message: "could not encode using utf8"))
    return result

  }

  guard let dkim_signature_data = Data(base64Encoded: parameters.signature) else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidEntryInDKIMHeader(message: "invalid base64 in signature ('b') entry"))
    return result
  }

  let signature_result: Bool
  do {
    switch parameters.algorithm {
    case DKIMSignatureAlgorithm.RSA_SHA1:
      signature_result = try DKIMVerifier.checkRSA_SHA1_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
    case DKIMSignatureAlgorithm.RSA_SHA256:
      signature_result = try DKIMVerifier.checkRSA_SHA256_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
    case DKIMSignatureAlgorithm.Ed25519_SHA256:
      signature_result = try DKIMVerifier.checkEd25519_SHA256_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
    }
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  if signature_result {
    if risks.count > 0 {
      result.status = DKIMStatus.Valid_Insecure(risks)
    } else {
      result.status = DKIMStatus.Valid
    }
  } else {
    result.status = DKIMStatus.Invalid(DKIMError.SignatureDoesNotMatch)
  }

  return result
}
