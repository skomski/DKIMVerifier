import Crypto
import Foundation
import RegularExpressions
import _CryptoExtras

enum DKIMError: Error, Equatable {
  case tagValueListParsingError(message: String)
  case RFC822MessageParsingError(message: String)
  case invalidRFC822Headers(message: String)
  case invalidEntryInDKIMHeader(message: String)
  case bodyHashDoesNotMatch(message: String)
  case invalidDNSEntry(message: String)
}

enum DKIMEncryption {
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

var dnsLoopupTxtFunction: (String) -> String? = { (domainName) in "fail" }

// generates the canonicalization data needed for signature
func generateSignedData(headers: OrderedKeyValueArray, includeHeaders: [String]) throws
  -> String
{
  var headers = headers

  var finalString: String = String()
  for includeHeader in includeHeaders {
    let index = headers.lastIndex(where: { $0.key.lowercased() == includeHeader })
    if index != nil {
      let result = headers.remove(at: index!)
      finalString += result.key + ":" + result.value
    }
  }
  let index = headers.lastIndex(where: { $0.key.lowercased() == "dkim-signature" })

  // remove the deposited signature (b\n=\nblalala to b=)
  // no leading crlf
  let FWS = #"(?:(?:\s*\r?\n)?\s+)?"#
  let RE_BTAG = #"([;\s]b"# + FWS + #"=)(?:"# + FWS + #"[a-zA-Z0-9+/=])*(?:\r?\n\Z)?"#
  let without_b = try headers[index!].value.regexSub(
    RE_BTAG, replacer: { (in, m) in m.groups[0]!.match })

  finalString += headers[index!].key + ":" + without_b.trailingTrim(.whitespacesAndNewlines)
  return finalString
}

func checkRSA_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> Bool
{
  let key = try _RSA.Signing.PublicKey.init(derRepresentation: encodedKey)
  let signature = _RSA.Signing.RSASignature.init(rawRepresentation: signature)

  return key.isValidSignature(
    signature, for: data,
    padding: _RSA.Signing.Padding.insecurePKCS1v1_5)
}

func checkEd25519_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> Bool
{
  let key = try Crypto.Curve25519.Signing.PublicKey.init(rawRepresentation: encodedKey)
  return key.isValidSignature(signature, for: Data(Crypto.SHA256.hash(data: data)))
}

public func verify(dnsLoopupTxtFunction: @escaping (String) -> String?, email_raw: String) throws
  -> Bool
{
  // seperate headers from body
  var (headers, body) = try parseRFC822Message(message: email_raw)

  guard !headers.isEmpty else {
    throw DKIMError.invalidRFC822Headers(message: "no headers")
  }

  guard headers.contains(where: { $0.key.lowercased() == "dkim-signature" }) else {
    throw DKIMError.invalidRFC822Headers(message: "no dkim signature")
  }

  let dkim_header_field: String = headers.last(where: { $0.key.lowercased() == "dkim-signature" }
  )!.value
  let tag_value_list: [String: String] = try parseTagValueList(
    raw_list: dkim_header_field)

  let canonicalization_header_method: DKIMCanonicalization
  let canonicalization_body_method: DKIMCanonicalization

  switch tag_value_list[DKIMTagNames.Canonicalization.rawValue] {
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
  default:
    canonicalization_header_method = DKIMCanonicalization.Simple
    canonicalization_body_method = DKIMCanonicalization.Simple
  }

  let encryption_method: DKIMEncryption
  let raw_encryption_method: String? = tag_value_list[DKIMTagNames.Algorithm.rawValue]
  if raw_encryption_method == "rsa-sha256" {
    encryption_method = DKIMEncryption.RSA_SHA256
  } else if raw_encryption_method == "ed25519-sha256" {
    encryption_method = DKIMEncryption.Ed25519_SHA256
  } else {
    throw DKIMError.invalidEntryInDKIMHeader(
      message:
        "signature algorithm is not rsa.sha256 or ed25519-sha256 - other currently not supported")
  }

  switch canonicalization_header_method {
  case DKIMCanonicalization.Simple:
    break
  case DKIMCanonicalization.Relaxed:
    throw DKIMError.invalidEntryInDKIMHeader(message: "relaxed not implemented")
  }

  switch canonicalization_body_method {
  case DKIMCanonicalization.Simple:
    body = try SimpleCanonicalizationBodyAlgorithm.canonicalize(body: body)
    break
  case DKIMCanonicalization.Relaxed:
    throw DKIMError.invalidEntryInDKIMHeader(message: "relaxed not implemented")
  }

  // check if the calculated body hash matches the deposited body hash in the DKIM Header
  let provided_hash = tag_value_list[DKIMTagNames.BodyHash.rawValue]!
  //print(Optional(body))
  let calculated_hash = Data(Crypto.SHA256.hash(data: body.data(using: .ascii)!))
    .base64EncodedString()

  guard provided_hash == calculated_hash else {
    throw DKIMError.bodyHashDoesNotMatch(
      message: "provided hash " + provided_hash + " not equal to calculated hash "
        + calculated_hash)
  }

  // use the defined selector and domain from the DKIM header to query the DNS public key entry
  let include_headers: [String] = try tag_value_list[DKIMTagNames.SignedHeaderFields.rawValue]!
    .regexSplit(#"\s*:\s*"#).map({
      $0.lowercased()
    })
  let domain =
    tag_value_list[DKIMTagNames.DomainSelector.rawValue]! + "._domainkey." + tag_value_list[
      DKIMTagNames.SDID.rawValue]!

  // use the provided dns loopkup function
  let record = dnsLoopupTxtFunction(domain)

  guard record != nil else {
    throw DKIMError.invalidDNSEntry(message: "DNS Entry is empty for domain: \(domain)")
  }

  let dns_tag_value_list = try parseTagValueList(raw_list: record!)

  guard let public_key_base64 = dns_tag_value_list[DNSEntryTagNames.PublicKey.rawValue] else {
    throw DKIMError.invalidDNSEntry(message: "no p entry")
  }

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
    throw DKIMError.invalidDNSEntry(message: "invalid base64 key")
  }

  // generate the signed data from the headers without the signature
  let raw_signed_string = try DKIMVerifier.generateSignedData(
    headers: headers, includeHeaders: include_headers)

  // print(Optional(raw_signed_string))

  guard let raw_signed_data = raw_signed_string.data(using: .ascii) else {
    throw DKIMError.invalidEntryInDKIMHeader(message: "could not convert to ascii")

  }

  guard let dkim_signature = tag_value_list[DKIMTagNames.Signature.rawValue] else {
    throw DKIMError.invalidEntryInDKIMHeader(message: "no b entry")
  }

  // extract the signature from the dkim header
  let dkim_signature_clean: String = try dkim_signature.regexSub(
    #"\s+"#, replacer: { num, m in "" })
  //    print(Optional(raw_signed_string))
  //    print(Optional(dkim_signature_clean))
  guard let dkim_signature_data = Data(base64Encoded: dkim_signature_clean) else {
    throw DKIMError.invalidEntryInDKIMHeader(message: "invalid base64 in signature ('b') entry")
  }

  switch encryption_method {
  case DKIMEncryption.RSA_SHA256:
    return try DKIMVerifier.checkRSA_SHA256_Signature(
      encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
  case DKIMEncryption.Ed25519_SHA256:
    return try DKIMVerifier.checkEd25519_SHA256_Signature(
      encodedKey: public_key_data, signature: dkim_signature_data, data: raw_signed_data)
  }
}
