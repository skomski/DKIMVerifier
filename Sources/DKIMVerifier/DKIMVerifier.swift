import Crypto
import Foundation
import Punycode
import RegularExpressions
import TLDExtract
import _CryptoExtras

public func verifyDKIMSignatures(
  dnsLoopupTxtFunction: @escaping DNSLookupFunctionType, email_raw: String,
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

  let extractResult = tldExtractor.parse(result.extractedDomainFromSender!)

  guard extractResult != nil && extractResult!.rootDomain != nil else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC5322Headers(
        message:
          "could not extract root domain out of extractedDomainFromSender \(result.extractedDomainFromSender!)"
      ))
    return result
  }

  let idnaencoded_domain = result.extractedDomainFromSender!.idnaEncoded

  guard idnaencoded_domain != nil else {
    result.status = DKIMStatus.Error(
      DKIMError.InvalidRFC5322Headers(
        message: "could not punyencoded extracted domain \(result.extractedDomainFromSender!)"))
    return result
  }

  result.extractedDomainFromSenderIdnaEncoded = idnaencoded_domain!

  guard headers.contains(where: { $0.key.lowercased() == "dkim-signature" }) else {
    result.status = DKIMStatus.Error(DKIMError.NoSignature)
    return result
  }

  for (index, header) in headers.enumerated() {
    if header.key.lowercased() != "dkim-signature" {
      continue
    }

    let signatureResult = verifyDKIMSignature(
      dnsLoopupTxtFunction: dnsLoopupTxtFunction,
      emailHeaders: headers, emailBody: body, dkimHeaderFieldIndex: index,
      extractedDomainFromSenderIdnaEncoded: result.extractedDomainFromSenderIdnaEncoded!)
    result.signatures.append(signatureResult)
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

    result.dmarcResult = checkDMARC(
      dnsLookupTxtFunction: dnsLoopupTxtFunction,
      fromSenderDomain: result.extractedDomainFromSender!, validDKIMDomains: validDKIMDomains)

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
  dnsLoopupTxtFunction: @escaping DNSLookupFunctionType,
  emailHeaders: OrderedKeyValueArray, emailBody: String, dkimHeaderFieldIndex: Int,
  extractedDomainFromSenderIdnaEncoded: String
) -> DKIMSignatureResult {
  var result: DKIMSignatureResult = DKIMSignatureResult.init(
    status: DKIMSignatureStatus.Error(DKIMError.UnexpectedError(message: "unset error")), info: nil,
    validatedWithDNSSEC: false)
  var risks: Set<DKIMRisks> = Set<DKIMRisks>.init()

  let dkimFields: TagValueDictionary

  do {
    dkimFields = try parseTagValueList(raw_list: emailHeaders[dkimHeaderFieldIndex].value)
  } catch let error as DKIMError {
    result.status = DKIMSignatureStatus.Error(error)
    return result
  } catch {
    result.status = DKIMSignatureStatus.Error(
      DKIMError.UnexpectedError(message: error.localizedDescription))
    return result
  }

  // validate dkim fields and add possible risks
  do {
    risks = risks.union(
      try validateDKIMFields(
        email_headers: emailHeaders, email_body: emailBody, dkimFields: dkimFields,
        dkim_result: &result,
        extractedDomainFromSenderIdnaEncoded: extractedDomainFromSenderIdnaEncoded))
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
    let dnsResult = try dnsLoopupTxtFunction(domain)
    record = dnsResult.result
    result.validatedWithDNSSEC = dnsResult.validatedWithDNSSEC
    if !dnsResult.validatedWithDNSSEC {
      risks.insert(DKIMRisks.ValidatedWithoutDNSSEC)
    }
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
    risks = risks.union(
      try validateDKIMSignatureDNSFields(
        dkimResult: &result, dnsFields: dns_tag_value_list,
        extractedDomainFromSenderIdnaEncoded: extractedDomainFromSenderIdnaEncoded))
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

  guard let public_key_data = Data(base64Encoded: result.dnsInfo!.publicKey)
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
