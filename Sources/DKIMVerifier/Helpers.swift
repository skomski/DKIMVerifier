import Foundation
import RegularExpressions
import TLDExtract

let tldExtractor = try! TLDExtract.init(useFrozenData: true)

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
      throw DKIMError.TagValueListParsingError(
        message: "no value for key: "
          + String(splitted[0].trimmingCharacters(in: .whitespacesAndNewlines)))
    }
    let key = splitted[0].trimmingCharacters(in: .whitespacesAndNewlines)
    let value = splitted[1].trimmingCharacters(in: .whitespacesAndNewlines)

    do {
      if try key.regexMatch(#"^[a-zA-Z](\w)*"#) == nil {
        throw DKIMError.TagValueListParsingError(
          message: "invalid characters in key: " + String(key))
      }
    } catch {
      throw DKIMError.TagValueListParsingError(message: "regexError for key: " + key)
    }

    if tags[key] != nil {
      throw DKIMError.TagValueListParsingError(message: "duplicate key: " + key)
    }
    tags[key] = value
  }

  return tags
}

// separates header and body for a RFC5322Message and parses the headers into a dictionary
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
        throw DKIMError.RFC5322MessageParsingError(message: "value for unknown header")
      }
      headers[headers.endIndex - 1].value += lines[i] + "\r\n"
    } else {
      do {
        let match = try lines[i].regexMatch(#"([\x21-\x7e]+?):"#)
        if match == nil {
          throw DKIMError.RFC5322MessageParsingError(
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
        throw DKIMError.RFC5322MessageParsingError(message: "regex error in line:" + String(i))
      }
    }

    i += 1
  }

  return (headers, lines[i...].joined(separator: "\r\n"))
}

// generates the canonicalization data needed for signature
func generateSignedData(
  dkimHeaderField: KeyValue, headers: OrderedKeyValueArray, includeHeaders: [String]
) throws
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

  // removes the signature data (b\n=\nblalala to b=)
  let FWS = #"(?:(?:\s*\r?\n)?\s+)?"#
  let RE_BTAG = #"([;\s]b"# + FWS + #"=)(?:"# + FWS + #"[a-zA-Z0-9+/=])*(?:\r?\n\Z)?"#
  let without_b = try dkimHeaderField.value.regexSub(
    RE_BTAG, replacer: { (_, m) in m.groups[0]!.match })

  finalString += dkimHeaderField.key + ":" + without_b.trailingTrim(.whitespacesAndNewlines)
  return finalString
}

/// relaxed check for an email address (utf-8 happy)
func checkEmailAddress(email_address: String) -> Bool {
  let regex = #"^[^@\s]+@[^@\s]+\.[^@\s]+$"#
  return (try? email_address.regexMatch(regex)) != nil
}

///  Extracts an email address from a From: Field
///  Only allows four formats:
///     plain: test@example.com
///     display name with quotes : "<test@example.com>" <test@example.com>
///     display name without quotes but disallow additional @ before <>:  Test <test@example.com>
///     only in quotes: <test@example.com>
///
///  TODO: more robust parser with warnings
func parseEmailFromField(raw_from_field: String) -> String? {
  let lowercased = raw_from_field.lowercased()
  let stripped = lowercased.trimmingCharacters(in: .whitespacesAndNewlines)
  // "display name" <test@example.de>
  var match: RegexMatch? = try? stripped.regexMatch(#"^\s*".*"\s*<(.+@[^@\s]+\.[^@\s]+)>[^@]*$"#)

  // display name but no @ before <>
  if match == nil {
    match = try? stripped.regexMatch(#"^[^@]*<(.+)>[^@]*$"#)
  }

  if let match: RegexMatch = match {
    if let group = match.groups[0] {
      let strippedMatch = group.match.trimmingCharacters(in: .whitespacesAndNewlines)
      if checkEmailAddress(email_address: strippedMatch) {
        return strippedMatch
      }
    }
  }

  // plain
  if checkEmailAddress(email_address: stripped) {
    return stripped
  }

  return nil
}

/// This functions extracts the domain name part from a email address
func parseDomainFromEmail(email: String) -> String? {
  let email = email.lowercased()

  guard checkEmailAddress(email_address: email) else {
    return nil
  }
  let result = email.split(separator: "@")
  if result.count != 2 {
    return nil
  }

  return String(result.last!)
}
