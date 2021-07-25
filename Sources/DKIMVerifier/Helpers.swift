import Foundation

extension String {
  func trailingTrim(_ characterSet: CharacterSet) -> String {
    if let range = rangeOfCharacter(from: characterSet, options: [.anchored, .backwards]) {
      return String(self[..<range.lowerBound]).trailingTrim(characterSet)
    }
    return self
  }
}

public struct KeyValue: Equatable {
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

internal func parseTagValueList(raw_list: String) throws -> TagValueDictionary {
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
internal func parseRFC822Message(message: String) throws -> (OrderedKeyValueArray, String) {
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
