import Foundation
import RegularExpressions

func strip_trailing_lines(text: String) throws -> String {
  return try text.regexSub("(\r\n)+$", replacer: { n, m in return "\r\n" })
}

func strip_trailing_whitespace(text: String) throws -> String {
  return try text.regexSub("[\t ]+\r\n", replacer: { n, m in return "\r\n" })
}

func compress_whitespace(text: String) throws -> String {
  return try text.regexSub("[\t ]+", replacer: { n, m in return " " })
}

func unfold_header_value(text: String) throws -> String {
  return try text.regexSub("\r\n", replacer: { n, m in return "" })
}

func correct_empty_body(text: String) throws -> String {
  if text == "\r\n" {
    return ""
  } else {
    return text
  }
}

protocol CanonicalizationHeaderAlgorithm {
  static func canonicalize(headers: OrderedKeyValueArray) throws -> OrderedKeyValueArray
}

class SimpleCanonicalizationHeaderAlgorithm: CanonicalizationHeaderAlgorithm {
  static func canonicalize(headers: OrderedKeyValueArray) throws -> OrderedKeyValueArray {
    headers
  }
}

class RelaxedCanonicalizationHeaderAlgorithm: CanonicalizationHeaderAlgorithm {
  static func canonicalize(headers: OrderedKeyValueArray) throws -> OrderedKeyValueArray {
    // Convert all header field names to lowercase.
    // Unfold all header lines.
    // Compress WSP to single space.
    // Remove all WSP at the start or end of the field value (strip).
    //      return [
    //          (x[0].lower().rstrip(),
    //           compress_whitespace(unfold_header_value(x[1])).strip() + b"\r\n")
    //          for x in headers]
    var headers = headers
    for index in headers.indices {
      headers[index].key = headers[index].key.lowercased().trimmingCharacters(in: .whitespaces)
      headers[index].value =
        try compress_whitespace(text: unfold_header_value(text: headers[index].value))
        .trimmingCharacters(
          in: .whitespacesAndNewlines) + "\r\n"
    }
    return headers
  }
}

protocol CanonicalizationBodyAlgorithm {
  static func canonicalize(body: String) throws -> String
}

class SimpleCanonicalizationBodyAlgorithm: CanonicalizationBodyAlgorithm {
  static func canonicalize(body: String) throws -> String {
    if body.count == 0 {
      return "\r\n"
    }
    return try strip_trailing_lines(text: body)
  }
}

class RelaxedCanonicalizationBodyAlgorithm: CanonicalizationBodyAlgorithm {
  static func canonicalize(body: String) throws -> String {
    // Remove all trailing WSP at end of lines.
    // Compress non-line-ending WSP to single space.
    // Ignore all empty lines at the end of the message body.
    // return correct_empty_body(strip_trailing_lines(
    //    compress_whitespace(strip_trailing_whitespace(body))))

    return try correct_empty_body(
      text: strip_trailing_lines(
        text: compress_whitespace(text: strip_trailing_whitespace(text: body))))
  }
}
