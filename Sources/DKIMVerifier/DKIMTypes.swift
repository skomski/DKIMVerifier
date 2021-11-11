import Crypto
import Foundation

public enum DKIMError: Error, Equatable {
  // email errors
  case TagValueListParsingError(message: String)
  case RFC5322MessageParsingError(message: String)
  case InvalidRFC5322Headers(message: String)
  case NoSignature
  case OnlyInvalidSignatures

  // signature errors
  case InvalidEntryInDKIMHeader(message: String)
  case BodyHashDoesNotMatch(message: String)
  case SignatureDoesNotMatch
  case InvalidDNSEntry(message: String)
  case PublicKeyRevoked
  case PublicKeyWithIncorrectParameters  // for example keySize lower than 1024 for RSA

  // always possible
  case UnexpectedError(message: String)
}

public enum DKIMSignatureAlgorithm {
  case RSA_SHA256
  case Ed25519_SHA256
}

public enum DKIMCanonicalization {
  case Simple
  case Relaxed
}

public enum DKIMPublicKeyQueryMethod {
  case DNSTXT
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
  // case BodyLength = "l"  // optional, ignored for BodyHash calculation because security risk
  case PublicKeyQueryMethod = "q"  // optional, only dns/txt
  case DomainSelector = "s"  // required
  case SignatureTimestamp = "t"  // optional
  case SignatureExpiration = "x"  // optional
  //case CopiedHeaderFields = "z"  // optional, unused in practice, rfc unclear
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

public enum DKIMSignatureStatus: Equatable {
  case Valid
  case Insecure(Set<DKIMRisks>)
  case Error(DKIMError)
}

public enum DKIMStatus: Equatable {
  case Valid
  case Insecure
  case Error(DKIMError)
}

public enum DKIMRisks: Hashable, Equatable {
  case SDIDNotInFrom(sdid: String, fromDomain: String)  // third-party signature, DKIM Domain not a subdomain or equal to From: E-Mail-Header
  case ImportantHeaderFieldNotSigned(name: String)  // only From: field required, but more fields are better else manipulation possible
  // Subject, Content-Type, Reply-To,... should be signed
  case InsecureKeySize(size: Int, expected: Int)  // using a key size less than 2048 for RSA
  case SignatureExpired(expirationDate: Date)  // Signature Expiration Parameter is in the past
  case ValidatedWithoutDNSSEC
  // Not accepted as a risk anymore (high risk, not used)
  //   -> Ignored in body hash validation, error on additional content
  // case UsingLengthParameter  // only verified to a specific body length

  // Not accepted as a risk anymore (RFC8301) -> Error
  // case UsingSHA1  // insecure hashing algorithm
}

var LowestSecureKeySize: Int = 2048

// The rfc6376 recommended header fields to sign
let importantHeaderFields: Set<String> = [
  "from", "sender", "reply-to", "subject", "date", "message-id", "to", "cc",
  "mime-version", "content-type", "content-transfer-encoding",
  "content-id", "content-description", "resent-date", "resent-from",
  "resent-sender", "resent-to", "resent-cc", "resent-message-id",
  "in-reply-to", "references", "list-id", "list-help", "list-unsubscribe",
  "list-subscribe", "list-post", "list-owner", "list-archive",
]

public struct DKIMSignatureInfo: Equatable {
  public var version: UInt
  public var algorithm: DKIMSignatureAlgorithm
  public var signature: String
  public var bodyHash: String
  public var headerCanonicalization: DKIMCanonicalization  // optional, but default simple
  public var bodyCanonicalization: DKIMCanonicalization  // optional, but default simple
  public var sdid: String
  public var signedHeaderFields: [String]
  public var domainSelector: String
  public var publicKeyQueryMethod: DKIMPublicKeyQueryMethod  // optional, but default dns/txt

  public var auid: String?
  // public var bodyLength: UInt?
  public var signatureTimestamp: Date?
  public var signatureExpiration: Date?
  //public var copiedHeaderFields: String?

  public var rsaKeySizeInBits: Int?
}

public struct DKIMSignatureResult: Equatable {
  public var status: DKIMSignatureStatus
  public var info: DKIMSignatureInfo?
  public var validatedWithDNSSEC: Bool = false
}

public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var signatures: [DKIMSignatureResult]
  public var emailFromSender: String?
  public var extractedDomainFromSender: String?
  public var DMARCResult: DMARCResult?

  init() {
    status = DKIMStatus.Error(DKIMError.UnexpectedError(message: "initial status"))
    signatures = []
    emailFromSender = nil
    extractedDomainFromSender = nil
  }

  init(status: DKIMStatus) {
    self.status = status
    signatures = []
    emailFromSender = nil
    extractedDomainFromSender = nil
  }
}

public struct DNSResult {
  public var result: String
  public var validatedWithDNSSEC: Bool

  public init(result: String, validatedWithDNSSEC: Bool) {
    self.result = result
    self.validatedWithDNSSEC = validatedWithDNSSEC
  }
}

public typealias DNSLookupFunctionType = (String) throws -> DNSResult
