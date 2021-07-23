import Foundation
import RegularExpressions

func strip_trailing_lines(text: String) throws -> String {
  return try text.regexSub("(\r\n)+$", replacer: { n, m in return "\r\n" })
}

protocol CanonicalizationHeaderAlgorithm {
  static func canonicalize(headers: OrderedKeyValueArray) throws -> OrderedKeyValueArray
}

class SimpleCanonicalizationHeaderAlgorithm: CanonicalizationHeaderAlgorithm {
  static func canonicalize(headers: OrderedKeyValueArray) throws -> OrderedKeyValueArray {
    headers
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
