import Foundation
import RegularExpressions

func strip_trailing_lines(text: String) throws -> String {
  return try text.regexSub("(\r\n)+$", replacer: { _, _ in return "\r\n" })
}

func strip_trailing_whitespace(text: String) throws -> String {
  return try text.regexSub("[\t ]+\r\n", replacer: { _, _ in return "\r\n" })
}

func compress_whitespace(text: String) throws -> String {
  return try text.regexSub("[\t ]+", replacer: { _, _ in return " " })
}

func unfold_header_value(text: String) throws -> String {
  return try text.regexSub("\r\n", replacer: { _, _ in return "" })
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
    return try correct_empty_body(
      text: strip_trailing_lines(
        text: compress_whitespace(text: strip_trailing_whitespace(text: body))))
  }
}
