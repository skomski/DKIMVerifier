import Crypto
import Foundation

public enum DKIMError: Error, Equatable {
  // email errors
  /// overall rfc5322 parsing error
  case RFC5322MessageParsingError(message: String)
  /// rfc5322 email headers failed to validate
  case InvalidRFC5322Headers(message: String)
  /// An important header is present several times, but should only be present once
  /// See: importantHeaderFields.
  case ImportantHeaderMultipleTimesDetected(header: String)
  /// No DKIM signature found in the email headers
  case NoSignature
  /// No valid or insecure signatures present in the email
  case OnlyInvalidSignatures

  // signature errors
  /// DKIM overall format failed to parse
  case TagValueListParsingError(message: String)
  /// DKIM specific entry failed to validate
  case InvalidEntryInDKIMHeader(message: String)
  /// Calculated body hash did not match the specified in the DKIM signature
  case BodyHashDoesNotMatch(message: String)
  /// Calculated signature did not match the specified in the DKIM signature
  case SignatureDoesNotMatch

  // dns entry errors
  case InvalidDNSEntry(message: String)
  /// An empty value for the public key entry ('p') means that this public key has been revoked.
  case PublicKeyRevoked
  /// Publiy key format incorrect.For example keySize lower than 1024 for RSA
  case PublicKeyWithIncorrectParameters(message: String)
  /// DNS flags entry with the value 'y' specifies DKIMTestMode. Should not handled different than unsigned mail
  case DKIMTestMode
  /// DNS flags entry with the value 's' present.
  /// Validation failed for the "i=" domain MUST NOT be a subdomain of "d=".
  case AUIDDomainPartMustBeEqualToSDIDValidationError

  // always possible
  /// Dependency error or not anticipated error
  case UnexpectedError(message: String)
}

public enum DKIMSignatureAlgorithm: String {
  case RSA_SHA256 = "rsa-sha256"
  case Ed25519_SHA256 = "ed25519-sha256"
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
  // case CopiedHeaderFields = "z"  // optional, unused in practice, rfc unclear
}

enum DNSEntryTagNames: String {
  case Version = "v"  // recommended
  case AcceptableHashAlgorithms = "h"  // optional
  case KeyType = "k"  // optional
  case Notes = "n"  // optional
  case PublicKey = "p"  // required
  case ServiceType = "s"  // optional
  case Flags = "t"  // optional
}

public enum DKIMHashAlgorithm: String {
  case SHA256 = "sha256"
}

public enum DKIMKeyType: String {
  case RSA = "rsa"
  case Ed25519 = "ed25519"
}

public enum DKIMServiceType: String {
  case All = "*"
  case Email = "email"
}

public enum DKIMSignatureDNSFlag: String {
  case TestMode = "y"  // This domain is testing DKIM. Verifiers should not handle emails differently from unsigned emails
  case AUIDDomainPartMustBeEqualToSDID = "s"  // That is, the "i=" domain MUST NOT be a subdomain of "d=".
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
  /// third-party signature, DKIM specified domain is not a subdomain or equal to From: E-Mail-Header
  case SDIDNotInFrom(sdid: String, fromDomain: String)
  /// The DKIM RFC only requires the  From: field to be signed, but more fields are recommend else manipulation possible
  /// Subject, Content-Type, Reply-To,... should be signed,  see importantHeaderFields
  case ImportantHeaderFieldNotSigned(name: String)
  /// Using a key size less than LowestSecureKeySize for RSA (default: 2048)
  case InsecureKeySize(size: Int, expected: Int)
  /// Signature Expiration Parameter is in the past
  case SignatureExpired(expirationDate: Date)
  /// could not validate dns requests with DNSSEC
  case ValidatedWithoutDNSSEC

  // Not accepted as a risk anymore (high risk, not used)
  //   -> Ignored in body hash validation, error on additional content
  // case UsingLengthParameter  // only verified to a specific body length

  // Not accepted as a risk anymore (RFC8301) -> Error
  // case UsingSHA1  // insecure hashing algorithm
}

/// Acceptable secure key size for RSA
var LowestSecureKeySize: Int = 2048

/// The rfc6376 recommended header fields to sign
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
  public var auid: String

  // public var bodyLength: UInt?
  public var signatureTimestamp: Date?
  public var signatureExpiration: Date?
  // public var copiedHeaderFields: String?

  public var rsaKeySizeInBits: Int?
}

public struct DKIMSignatureDNSInfo: Equatable {
  public var publicKey: String  // required

  public var version: String?  // optional
  public var acceptableHashAlgorithms: [DKIMHashAlgorithm]?  // optional
  public var keyType: DKIMKeyType?  // optional
  public var notes: String?  // optional
  public var serviceType: [DKIMServiceType]?  // optional
  public var flags: [DKIMSignatureDNSFlag]?  // optional
}

public struct DKIMSignatureResult: Equatable {
  public var status: DKIMSignatureStatus
  public var info: DKIMSignatureInfo?
  public var dnsInfo: DKIMSignatureDNSInfo?
  public var validatedWithDNSSEC: Bool = false
}

public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var signatures: [DKIMSignatureResult]

  public var emailFromSender: String?
  public var extractedDomainFromSender: String?
  public var extractedDomainFromSenderIdnaEncoded: String?

  public var dmarcResult: DMARCResult?

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
