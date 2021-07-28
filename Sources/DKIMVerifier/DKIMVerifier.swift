import Crypto
import Foundation
import RegularExpressions
import _CryptoExtras

public enum DKIMError: Error, Equatable {
  case tagValueListParsingError(message: String)
  case RFC822MessageParsingError(message: String)
  case invalidRFC822Headers(message: String)
  case invalidEntryInDKIMHeader(message: String)
  case bodyHashDoesNotMatch(message: String)
  case invalidDNSEntry(message: String)
  case NoErrorSet
  case UnexpectedError(message: String)
}

enum DKIMEncryption {
  case RSA_SHA1
  case RSA_SHA256
  case Ed25519_SHA256
}

enum DKIMCanonicalization {
  case Simple
  case Relaxed
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

public enum DKIMRisks: Equatable {
  case UsingLengthParameter  // only verified to a specific body length
  case UsingSHA1  // insecure hashing algorithm
  case SDIDNotEqualToSender  // third-party signature, From: Sender different to DKIM Domain
  case FewHeaderFieldsSigned  // only From: field required, but more fields are better else manipulation possible
  // Subject, Content-Type, Reply-To,... should be signed
}

public struct DKIMInfo: Equatable {
  var version: String?
  var sdid: String?
  var auid: String?
  var from_sender: String?
}

public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var info: DKIMInfo?

  init() {
    status = DKIMStatus.Error(DKIMError.NoErrorSet)
    info = DKIMInfo.init()
  }

  init(status: DKIMStatus) {
    self.status = status
    info = DKIMInfo.init()
  }
}

var dnsLoopupTxtFunction: (String) -> String? = { (domainName) in "fail" }

func validate_dkim_fields(
  email_headers: OrderedKeyValueArray, email_body: String, dkim_fields: TagValueDictionary
) throws -> Set<DKIMRisks> {
  var risks: Set<DKIMRisks> = Set<DKIMRisks>.init()

  if dkim_fields[DKIMTagNames.BodyLength.rawValue] != nil {
    risks.insert(DKIMRisks.UsingLengthParameter)
  }

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
      DKIMError.invalidRFC822Headers(message: "invalid email without header"))
    return result
  }

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
        email_headers: headers, email_body: body, dkim_fields: tag_value_list))
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  let canonicalization_header_method: DKIMCanonicalization
  let canonicalization_body_method: DKIMCanonicalization

  let canonicalization_value = tag_value_list[DKIMTagNames.Canonicalization.rawValue]

  switch canonicalization_value {
  case "relaxed":
    canonicalization_header_method = DKIMCanonicalization.Relaxed
    canonicalization_body_method = DKIMCanonicalization.Simple
  case "relaxed/relaxed":
    canonicalization_header_method = DKIMCanonicalization.Relaxed
    canonicalization_body_method = DKIMCanonicalization.Relaxed
  case "simple/relaxed":
    canonicalization_header_method = DKIMCanonicalization.Simple
    canonicalization_body_method = DKIMCanonicalization.Relaxed
  case "relaxed/simple":
    canonicalization_header_method = DKIMCanonicalization.Relaxed
    canonicalization_body_method = DKIMCanonicalization.Simple
  case nil, "simple/simple":
    canonicalization_header_method = DKIMCanonicalization.Simple
    canonicalization_body_method = DKIMCanonicalization.Simple
  default:
    result.status = DKIMStatus.Error(
      DKIMError.invalidEntryInDKIMHeader(
        message:
          "invalid canonicalization value \(canonicalization_value!) provided ('c')")
    )
    return result
  }

  let encryption_method: DKIMEncryption
  let raw_encryption_method: String? = tag_value_list[DKIMTagNames.Algorithm.rawValue]
  if raw_encryption_method == "rsa-sha256" {
    encryption_method = DKIMEncryption.RSA_SHA256
  } else if raw_encryption_method == "ed25519-sha256" {
    encryption_method = DKIMEncryption.Ed25519_SHA256
  } else if raw_encryption_method == "rsa-sha1" {
    encryption_method = DKIMEncryption.RSA_SHA1
    risks.insert(DKIMRisks.UsingSHA1)
  } else {
    result.status = DKIMStatus.Error(
      DKIMError.invalidEntryInDKIMHeader(
        message:
          "invalid signature algorithm provided \(raw_encryption_method ?? "none") ('a') (rsa-sha256, ed25519-sha256, rsa-sha1 supported"
      )
    )
    return result
  }

  do {
    switch canonicalization_header_method {
    case DKIMCanonicalization.Simple:
      headers = try SimpleCanonicalizationHeaderAlgorithm.canonicalize(headers: headers)
    case DKIMCanonicalization.Relaxed:
      headers = try RelaxedCanonicalizationHeaderAlgorithm.canonicalize(headers: headers)
    }

    switch canonicalization_body_method {
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

  // check if the calculated body hash matches the deposited body hash in the DKIM Header
  let provided_hash = tag_value_list[DKIMTagNames.BodyHash.rawValue]!
  //print(Optional(body))
  let calculated_hash: String
  switch encryption_method {
  case DKIMEncryption.RSA_SHA1:
    calculated_hash = Data(Crypto.Insecure.SHA1.hash(data: body.data(using: .utf8)!))
      .base64EncodedString()
  case DKIMEncryption.RSA_SHA256, DKIMEncryption.Ed25519_SHA256:
    calculated_hash = Data(Crypto.SHA256.hash(data: body.data(using: .utf8)!))
      .base64EncodedString()
  }

  guard provided_hash == calculated_hash else {
    result.status = DKIMStatus.Invalid(
      DKIMError.bodyHashDoesNotMatch(
        message: "provided hash " + provided_hash + " not equal to calculated hash "
          + calculated_hash))
    return result
  }

  guard let signed_header_fields = tag_value_list[DKIMTagNames.SignedHeaderFields.rawValue] else {
    result.status = DKIMStatus.Error(
      DKIMError.invalidEntryInDKIMHeader(message: "missing required signed header field (h)"))
    return result
  }

  guard let domain_selector = tag_value_list[DKIMTagNames.DomainSelector.rawValue] else {
    result.status = DKIMStatus.Error(
      DKIMError.invalidEntryInDKIMHeader(message: "missing required domain selector field (d)"))
    return result
  }

  guard let sdid = tag_value_list[DKIMTagNames.SDID.rawValue] else {
    result.status = DKIMStatus.Error(
      DKIMError.invalidEntryInDKIMHeader(message: "missing required sdid field (s)"))
    return result
  }

  // use the defined selector and domain from the DKIM header to query the DNS public key entry
  let include_headers: [String]
  do {
    include_headers =
      try signed_header_fields
      .regexSplit(#"\s*:\s*"#).map({
        $0.lowercased()
      })
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }
  let domain = domain_selector + "._domainkey." + sdid

  // use the provided dns loopkup function
  let record: String
  do {
    let tempRecord = try dnsLoopupTxtFunction(domain)
    guard tempRecord != nil else {
      result.status = DKIMStatus.Error(
        DKIMError.invalidDNSEntry(message: "DNS Entry is empty for domain: \(domain)"))
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
      DKIMError.invalidDNSEntry(message: "no public key dns entry (p)"))
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
      DKIMError.invalidDNSEntry(message: "invalid base64 encoding for public key"))
    return result
  }

  let raw_signed_string: String

  // generate the signed data from the headers without the signature
  do {
    raw_signed_string = try DKIMVerifier.generateSignedData(
      headers: headers, includeHeaders: include_headers)
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
      DKIMError.invalidEntryInDKIMHeader(message: "could not encode using utf8"))
    return result

  }

  guard let dkim_signature = tag_value_list[DKIMTagNames.Signature.rawValue] else {
    result.status = DKIMStatus.Error(DKIMError.invalidEntryInDKIMHeader(message: "no b entry"))
    return result
  }

  let dkim_signature_clean: String
  // extract the signature from the dkim header
  do {
    dkim_signature_clean = try dkim_signature.regexSub(
      #"\s+"#, replacer: { num, m in "" })
  } catch let error as DKIMError {
    result.status = DKIMStatus.Error(error)
    return result
  } catch {
    result.status = DKIMStatus.Error(DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }
  // print(raw_signed_string)
  // print(Optional(dkim_signature_clean))
  guard let dkim_signature_data = Data(base64Encoded: dkim_signature_clean) else {
    result.status = DKIMStatus.Error(
      DKIMError.invalidEntryInDKIMHeader(message: "invalid base64 in signature ('b') entry"))
    return result
  }

  let signature_result: Bool
  do {
    switch encryption_method {
    case DKIMEncryption.RSA_SHA1:
      signature_result = try DKIMVerifier.checkRSA_SHA1_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
    case DKIMEncryption.RSA_SHA256:
      signature_result = try DKIMVerifier.checkRSA_SHA256_Signature(
        encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
    case DKIMEncryption.Ed25519_SHA256:
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

  if signature_result && risks.count > 0 {
    result.status = DKIMStatus.Valid_Insecure(risks)
  } else {
    result.status = DKIMStatus.Valid
  }

  return result
}
