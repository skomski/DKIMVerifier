import Foundation
import Foundation
import CryptoKit
import RegularExpressions
import CryptorRSA
import dnssd

extension String {
    func trailingTrim(_ characterSet : CharacterSet) -> String {
        if let range = rangeOfCharacter(from: characterSet, options: [.anchored, .backwards]) {
            return self.substring(to: range.lowerBound).trailingTrim(characterSet)
        }
        return self
    }
}

public struct DKIMVerifier {
    public init() {
        
    }

    typealias DNSLookupHandler = ([String: String]?) -> Void

    func queryDNSTXTEntry(domainName: String) -> String? {
        var result: [String: String] = [:]
        var recordHandler: DNSLookupHandler = {
            (record) -> Void in
            if (record != nil) {
                for (k, v) in record! {
                    result.updateValue(v, forKey: k)
                }
            }
        }

        let callback: DNSServiceQueryRecordReply = {
            (sdRef, flags, interfaceIndex, errorCode, fullname, rrtype, rrclass, rdlen, rdata, ttl, context) -> Void in
            guard let handlerPtr = context?.assumingMemoryBound(to: DNSLookupHandler.self) else {
                return
            }
            let handler = handlerPtr.pointee
            if (errorCode != kDNSServiceErr_NoError) {
                return
            }
            guard let txtPtr = rdata?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            let txt = String(cString: txtPtr.advanced(by: 1))
            var record: [String: String] = [:]
            record["result"] = txt
            handler(record)
        }
        
        let serviceRef: UnsafeMutablePointer<DNSServiceRef?> = UnsafeMutablePointer.allocate(capacity: MemoryLayout<DNSServiceRef>.size)
        let code = DNSServiceQueryRecord(serviceRef, kDNSServiceFlagsTimeout, 0, domainName, UInt16(kDNSServiceType_TXT), UInt16(kDNSServiceClass_IN), callback, &recordHandler)
        if (code != kDNSServiceErr_NoError) {
            return nil
        }
        DNSServiceProcessResult(serviceRef.pointee)
        DNSServiceRefDeallocate(serviceRef.pointee)
        
        return result["result"]
    }

    enum DKIMError: Error {
        case invalidCharactersInRFC822MessageHeader(lineNumber: Int)
        case invalidRFC822Headers(message: String)
        case invalidEntryInDKIMHeader(message: String)
        case invalidTagListInDKIMHeader(tag: String)
        case bodyHashDoesNotMatch(message: String)
        case invalidDNSEntry(message: String)
    }

    func parseTagValueList(raw_list: String) throws -> Dictionary<String, String> {
        var tags : [String: String] = [:]
        
        let trimmed_raw_list = raw_list.trimmingCharacters(in: .whitespacesAndNewlines)
        let tag_specs = trimmed_raw_list.split(separator: ";", omittingEmptySubsequences: true)

        for tag_spec in tag_specs {
            let splitted = tag_spec.split(separator: "=", maxSplits: 1)
            if splitted.count != 2 {
                throw DKIMError.invalidTagListInDKIMHeader(tag: String(splitted[0]))
            }
            let key = splitted[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let value = splitted[1].trimmingCharacters(in: .whitespacesAndNewlines)
            
            do {
                    if try key.regexMatch(#"^[a-zA-Z](\w)*"#) == nil {
                        throw DKIMError.invalidTagListInDKIMHeader(tag: String(key))
                   }
            }
            catch {
                throw DKIMError.invalidTagListInDKIMHeader(tag: key)
            }
            
            if tags[key] != nil {
                throw DKIMError.invalidTagListInDKIMHeader(tag: key)
            }
            tags[key] = value
        }
        
        return tags
    }

    // separates header and body for a RFC822Message and parses the headers into a dictionary
    func parseRFC822Message(message: String) throws -> (Dictionary<String, String>, String) {
        var headers : [String: String] = [:]

        let lines = try message.regexSplit(#"\r?\n"#)
        var i = 0
        var lastHeader = ""
        while i < lines.count {
            if lines[i].isEmpty {
                i += 1
                break
            }
            
            if [Character("\t"),Character(" ")].contains(lines[i][lines[i].startIndex])  {
                if headers[lastHeader] == nil {
                    throw DKIMError.invalidCharactersInRFC822MessageHeader(lineNumber: i)
                }
                headers[lastHeader]! += lines[i] + "\r\n"
            } else {
                do {
                    let match = try lines[i].regexMatch(#"([\x21-\x7e]+?):"#)
                    if match == nil {
                        throw DKIMError.invalidCharactersInRFC822MessageHeader(lineNumber: 0)
                    }

                    let header_name = match!.groups[0]!.match
                    lastHeader = header_name
                    headers[header_name] = String(lines[i][lines[i].index(header_name.endIndex, offsetBy: 1)...]) + "\r\n"
                } catch {
                    throw DKIMError.invalidCharactersInRFC822MessageHeader(lineNumber: i)
                }
            }
            
            i += 1
        }
        

        return (headers, lines[i...].joined(separator: "\r\n"))
    }

    // generates the canonicalization data needed for signature
    func generateSignedData(headers: [String: String], includeHeaders: [String]) throws -> String {
        var headers = headers
        
        var finalString : String = String()
        for includeHeader in includeHeaders {
            let result = headers.first(where: {$0.key.lowercased() == includeHeader});
            if result != nil  {
                headers.removeValue(forKey: result!.key)
                finalString += result!.key + ":" + result!.value
            }
        }
        let result = headers.first(where: {$0.key.lowercased() == "dkim-signature"});

        // remove the deposited signature (b\n=\nblalala to b=)
        // no leading crlf
        let FWS = #"(?:(?:\s*\r?\n)?\s+)?"#
        let RE_BTAG = #"([;\s]b"# + FWS + #"=)(?:"# + FWS + #"[a-zA-Z0-9+/=])*(?:\r?\n\Z)?"#
        let without_b = try result!.value.regexSub(RE_BTAG, replacer: {(in, m) in m.groups[0]!.match})

        finalString += result!.key + ":" + without_b.trailingTrim(.whitespacesAndNewlines)
        return finalString
    }

    
    public func verify(email_raw: String) throws -> Bool {
        // seperate headers from body
        let (headers, body) = try parseRFC822Message(message: email_raw)
        
        guard !headers.isEmpty else {
            throw DKIMError.invalidRFC822Headers(message: "no headers")
        }
        
        guard headers["DKIM-Signature"] != nil else {
            throw DKIMError.invalidRFC822Headers(message: "no dkim signature")
        }
        
        let dkim_header_field : String = headers["DKIM-Signature"]!
        let tag_value_list : [String : String] = try parseTagValueList(raw_list: dkim_header_field)
        
        guard tag_value_list["c"] == "simple/simple" else {
            throw DKIMError.invalidEntryInDKIMHeader(message: "canonicalization algorithm is not simple/simple - other currently not implemented")
        }
        
        guard tag_value_list["a"] == "rsa-sha256" else {
            throw DKIMError.invalidEntryInDKIMHeader(message: "signature algorithm is not rsa.sha256 - other currently not implemented")
        }

        // check if the calculated body hash matches the deposited body hash in the DKIM Header
        let provided_hash = tag_value_list["bh"]!
        let calculated_hash = Data(SHA256.hash(data: body.data(using: .ascii)!)).base64EncodedString()

        guard provided_hash == calculated_hash else {
            throw DKIMVerifier.DKIMError.bodyHashDoesNotMatch(message: provided_hash + " not equal to " + calculated_hash)
        }

        // use the defined selector and domain from the DKIM header to query the DNS public key entry
        let include_headers : [String] = try tag_value_list["h"]!.regexSplit(#"\s*:\s*"#).map({ $0.lowercased() })
        let domain = tag_value_list["s"]! + "._domainkey." + tag_value_list["d"]!
        let record = queryDNSTXTEntry(domainName: domain)

        guard record != nil else {
            throw DKIMError.invalidDNSEntry(message: "DNS Entry is empty for domain: \(domain)")
        }

        let dns_tag_value_list = try parseTagValueList(raw_list: record!)

        //let key_raw = try String(contentsOf: URL(fileURLWithPath: DKIMVerifier().testkeydns_entry), encoding: .ascii)
        //let dns_tag_value_list : [String : String] = try parseTagValueList(raw_list: key_raw)
        //print(dns_tag_value_list)

        let base64key = dns_tag_value_list["p"]!
        //let pubKeyData : Data = base64key.data(using: .ascii)!
        let key = try CryptorRSA.createPublicKey(withBase64: base64key)

        // generate the signed data from the headers without the signature
        let raw_signeddata = try generateSignedData(headers: headers, includeHeaders: include_headers)
        let signeddata = try CryptorRSA.createPlaintext(with: raw_signeddata, using: .ascii)
        
        // extract the signature from the dkim header
        let b_valid : String = try tag_value_list["b"]!.regexSub(#"\s+"#, replacer: { num, m in "" })
        let signature = CryptorRSA.createSigned(with: Data(base64Encoded: b_valid)!)
        
        return try signeddata.verify(with: key, signature: signature, algorithm: .sha256)
    }
}
