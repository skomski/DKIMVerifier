import Crypto
import Foundation
import RegularExpressions
import _CryptoExtras

extension String {
  func trailingTrim(_ characterSet: CharacterSet) -> String {
    if let range = rangeOfCharacter(from: characterSet, options: [.anchored, .backwards]) {
      return String(self[..<range.lowerBound]).trailingTrim(characterSet)
    }
    return self
  }
}

public struct DKIMVerifier {
  struct KeyValue: Equatable {
    var key: String
    var value: String

    public init(key: String, value: String) {
      self.key = key
      self.value = value
    }

    static func == <T: StringProtocol>(s: KeyValue, tuple: (T, T)) -> Bool {
      return (s.key == tuple.0) && (s.value == tuple.1)
    }
  }
  typealias OrderedKeyValueArray = [KeyValue]
  typealias TagValueDictionary = [String: String]

  var dnsLoopupTxtFunction: (String) -> String? = { (domainName) in "fail" }

  public init(dnsLoopupTxtFunction: @escaping (String) -> String?) {
    self.dnsLoopupTxtFunction = dnsLoopupTxtFunction
  }

  // typealias DNSLookupHandler = ([String: String]?) -> Void

  // func queryDNSTXTEntry(domainName: String) -> String? {
  //     var result: [String: String] = [:]
  //     var recordHandler: DNSLookupHandler = {
  //         (record) -> Void in
  //         if (record != nil) {
  //             for (k, v) in record! {
  //                 result.updateValue(v, forKey: k)
  //             }
  //         }
  //     }

  //     let callback: DNSServiceQueryRecordReply = {
  //         (sdRef, flags, interfaceIndex, errorCode, fullname, rrtype, rrclass, rdlen, rdata, ttl, context) -> Void in
  //         guard let handlerPtr = context?.assumingMemoryBound(to: DNSLookupHandler.self) else {
  //             return
  //         }
  //         let handler = handlerPtr.pointee
  //         if (errorCode != kDNSServiceErr_NoError) {
  //             return
  //         }
  //         guard let txtPtr = rdata?.assumingMemoryBound(to: UInt8.self) else {
  //             return
  //         }
  //         let txt = String(cString: txtPtr.advanced(by: 1))
  //         var record: [String: String] = [:]
  //         record["result"] = txt
  //         handler(record)
  //     }

  //     let serviceRef: UnsafeMutablePointer<DNSServiceRef?> = UnsafeMutablePointer.allocate(capacity: MemoryLayout<DNSServiceRef>.size)
  //     let code = DNSServiceQueryRecord(serviceRef, kDNSServiceFlagsTimeout, 0, domainName, UInt16(kDNSServiceType_TXT), UInt16(kDNSServiceClass_IN), callback, &recordHandler)
  //     if (code != kDNSServiceErr_NoError) {
  //         return nil
  //     }
  //     DNSServiceProcessResult(serviceRef.pointee)
  //     DNSServiceRefDeallocate(serviceRef.pointee)

  //     return result["result"]
  // }

  enum DKIMError: Error, Equatable {
    case tagValueListParsingError(message: String)
    case RFC822MessageParsingError(message: String)
    case invalidRFC822Headers(message: String)
    case invalidEntryInDKIMHeader(message: String)
    case bodyHashDoesNotMatch(message: String)
    case invalidDNSEntry(message: String)
  }

  static func parseTagValueList(raw_list: String) throws -> TagValueDictionary {
    var tags: TagValueDictionary = [:]

    let trimmed_raw_list = raw_list.trimmingCharacters(in: .whitespacesAndNewlines)
    let tag_specs = trimmed_raw_list.split(separator: ";", omittingEmptySubsequences: true)

    for tag_spec in tag_specs {
      let splitted = tag_spec.split(separator: "=", maxSplits: 1)
      if splitted.count != 2 {
        throw DKIMError.tagValueListParsingError(
          message: "no value for key: " + String(splitted[0]))
      }
      let key = splitted[0].trimmingCharacters(in: .whitespacesAndNewlines)
      let value = splitted[1].trimmingCharacters(in: .whitespacesAndNewlines)

      do {
        if try key.regexMatch(#"^[a-zA-Z](\w)*"#) == nil {
          throw DKIMError.tagValueListParsingError(
            message: "invalid characters in key: " + String(key))
        }
      } catch {
        throw DKIMError.tagValueListParsingError(message: "regexError for key: " + key)
      }

      if tags[key] != nil {
        throw DKIMError.tagValueListParsingError(message: "duplicate key: " + key)
      }
      tags[key] = value
    }

    return tags
  }

  // separates header and body for a RFC822Message and parses the headers into a dictionary
  static func parseRFC822Message(message: String) throws -> (OrderedKeyValueArray, String) {
    var headers: OrderedKeyValueArray = []

    let lines = try message.regexSplit(#"\r?\n"#)
    var i = 0

    while i < lines.count {
      if lines[i].isEmpty {
        i += 1
        break
      }

      if [Character("\t"), Character(" ")].contains(lines[i][lines[i].startIndex]) {
        if headers.isEmpty {
          throw DKIMError.RFC822MessageParsingError(message: "value for unknown header")
        }
        headers[headers.endIndex - 1].value += lines[i] + "\r\n"
      } else {
        do {
          let match = try lines[i].regexMatch(#"([\x21-\x7e]+?):"#)
          if match == nil {
            throw DKIMError.RFC822MessageParsingError(
              message: "invalid header in line: " + String(i))
          }

          let header_name = match!.groups[0]!.match
          headers += [
            KeyValue(
              key: header_name,
              value: String(lines[i][lines[i].index(header_name.endIndex, offsetBy: 1)...]) + "\r\n"
            )
          ]
        } catch {
          throw DKIMError.RFC822MessageParsingError(message: "regex error in line:" + String(i))
        }
      }

      i += 1
    }

    return (headers, lines[i...].joined(separator: "\r\n"))
  }

  // generates the canonicalization data needed for signature
  static func generateSignedData(headers: OrderedKeyValueArray, includeHeaders: [String]) throws
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

  enum DKIMEncryption {
    case RSA_SHA256
    case Ed25519_SHA256
  }

  static func checkRSA_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
    -> Bool
  {
    let key = try _RSA.Signing.PublicKey.init(derRepresentation: encodedKey)
    let signature = _RSA.Signing.RSASignature.init(rawRepresentation: signature)

    return key.isValidSignature(
      signature, for: data,
      padding: _RSA.Signing.Padding.insecurePKCS1v1_5)
  }

  static func checkEd25519_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
    -> Bool
  {
    let key = try Crypto.Curve25519.Signing.PublicKey.init(rawRepresentation: encodedKey)
    return key.isValidSignature(signature, for: Data(Crypto.SHA256.hash(data: data)))
  }

  public func verify(email_raw: String) throws -> Bool {
    // seperate headers from body
    let (headers, body) = try DKIMVerifier.parseRFC822Message(message: email_raw)

    guard !headers.isEmpty else {
      throw DKIMError.invalidRFC822Headers(message: "no headers")
    }

    guard headers.contains(where: { $0.key.lowercased() == "dkim-signature" }) else {
      throw DKIMError.invalidRFC822Headers(message: "no dkim signature")
    }

    let dkim_header_field: String = headers.last(where: { $0.key.lowercased() == "dkim-signature" }
    )!.value
    let tag_value_list: [String: String] = try DKIMVerifier.parseTagValueList(
      raw_list: dkim_header_field)

    guard tag_value_list["c"] == "simple/simple" else {
      throw DKIMError.invalidEntryInDKIMHeader(
        message: "canonicalization algorithm is not simple/simple - other currently not implemented"
      )
    }

    let encryption_method: DKIMEncryption
    if tag_value_list["a"] == "rsa-sha256" {
      encryption_method = DKIMEncryption.RSA_SHA256
    } else if tag_value_list["a"] == "ed25519-sha256" {
      encryption_method = DKIMEncryption.Ed25519_SHA256
    } else {
      throw DKIMError.invalidEntryInDKIMHeader(
        message:
          "signature algorithm is not rsa.sha256 or ed25519-sha256 - other currently not supported")
    }

    // check if the calculated body hash matches the deposited body hash in the DKIM Header
    let provided_hash = tag_value_list["bh"]!
    //print(Optional(body))
    let calculated_hash = Data(Crypto.SHA256.hash(data: body.data(using: .ascii)!))
      .base64EncodedString()

    guard provided_hash == calculated_hash else {
      throw DKIMVerifier.DKIMError.bodyHashDoesNotMatch(
        message: "provided hash " + provided_hash + " not equal to calculated hash "
          + calculated_hash)
    }

    // use the defined selector and domain from the DKIM header to query the DNS public key entry
    let include_headers: [String] = try tag_value_list["h"]!.regexSplit(#"\s*:\s*"#).map({
      $0.lowercased()
    })
    let domain = tag_value_list["s"]! + "._domainkey." + tag_value_list["d"]!

    // use the provided dns loopkup function
    let record = self.dnsLoopupTxtFunction(domain)

    guard record != nil else {
      throw DKIMError.invalidDNSEntry(message: "DNS Entry is empty for domain: \(domain)")
    }

    let dns_tag_value_list = try DKIMVerifier.parseTagValueList(raw_list: record!)

    guard let public_key_base64 = dns_tag_value_list["p"] else {
      throw DKIMError.invalidDNSEntry(message: "no p entry")
    }

    guard let dns_encryption_type = dns_tag_value_list["k"] else {
      throw DKIMError.invalidDNSEntry(message: "no k entry")
    }

    switch encryption_method {
    case DKIMEncryption.Ed25519_SHA256:
      guard dns_encryption_type == "ed25519" else {
        throw DKIMError.invalidDNSEntry(message: "email encryption different from dns encryption")
      }
    case DKIMEncryption.RSA_SHA256:
      guard dns_encryption_type == "rsa" else {
        throw DKIMError.invalidDNSEntry(message: "email encryption different from dns encryption")
      }
    }

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

    guard let dkim_signature = tag_value_list["b"] else {
      throw DKIMError.invalidEntryInDKIMHeader(message: "no b entry")
    }

    // extract the signature from the dkim header
    let dkim_signature_clean: String = try dkim_signature.regexSub(
      #"\s+"#, replacer: { num, m in "" })
    //    print(Optional(raw_signed_string))
    //    print(Optional(dkim_signature_clean))
    guard let dkim_signature_data = Data(base64Encoded: dkim_signature_clean) else {
      throw DKIMError.invalidEntryInDKIMHeader(message: "invalid base64 in b entry")
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
}
