import Foundation
import Peppermint
import SwiftParsec

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
  -> String {
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

func parseEmailFromField(raw_from_field: String) -> String? {
  let noneOf = StringParser.noneOf
  let character = StringParser.character

  let quotedChars =
    noneOf("\\\"") <|> (StringParser.string("\\\"").attempt *> GenericParser(result: "\""))

  let quote = character("\"")
  let quotedField = quote *> quotedChars.many.stringValue <* (quote <?> "quote at end of field")

  let displayName = quotedField <|> noneOf("<").many.stringValue

  let field = (displayName *> StringParser.spaces *> character("<") *> noneOf(">").many.stringValue)

  let result: String
  do {
    result = try field.run(sourceName: "", input: raw_from_field)
  } catch {
    let predicate = EmailPredicate()
    if predicate.evaluate(with: raw_from_field) {
      return raw_from_field
    }
    return nil
  }

  return result
}

/// This functions extracts the domain name part from a email address
func parseDomainFromEmail(email: String) -> String? {
  let email = email.lowercased()
  let predicate = EmailPredicate()
  guard predicate.evaluate(with: email) else {
    return nil
  }
  let result = email.split(separator: "@")
  if result.count != 2 {
    return nil
  }

  return String(result.last!)
}
