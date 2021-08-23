# DKIMVerifier (Swift)

### WIP!

## Features

* Verification of DKIM signatures (https://datatracker.ietf.org/doc/html/rfc6376)
* No boolean result: Additional detection of DKIM security pitfalls
  * DKIM has user-configurable parameters that can make a valid DKIM signature pretty useless and this library strives to point out this misconfigured signatures
  * More info: https://github.com/skomski/DKIMVerifier/issues/10
* DMARC Alignment Policy Verification
  * additionally checks if the DMARC DKIM Alignment policy is correct for valid DKIM signatures

## API

###  DKIM Verification

```swift
DKIMVerifier.verifyDKIMSignatures(
  dnsLoopupTxtFunction: @escaping (String) throws -> String?, mail: String,
  verifyDMARCAlignment: Bool = false
)
  -> DKIMResult
```

Arguments:
* dnsLookupTxtFunction: should return txt value for specific domain
* mail: RFC5322 Message as raw string
* verifyDMARCAlignment: additional verify DMARC DKIM Alignment for valid signatures (default: false)

Result:
```swift
public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var signatures: [DKIMSignatureResult]
  public var emailFromSender: String?
  public var extractedDomainFromSender: String?
  public var DMARCResult: DMARCResult?
}

public struct DKIMSignatureResult: Equatable {
  public var status: DKIMSignatureStatus
  public var info: DKIMSignatureInfo?
}

public enum DKIMSignatureStatus: Equatable {
  case Valid
  case Valid_Insecure(Set<DKIMRisks>)
  case Invalid(DKIMError)
  case Error(DKIMError)
}

public enum DKIMStatus: Equatable {
  case Valid
  case Valid_Insecure
  case Invalid
  case NoSignature
  case Error(DKIMError)
}

public enum DKIMError: Error, Equatable {
  case TagValueListParsingError(message: String)
  case RFC5322MessageParsingError(message: String)
  case InvalidRFC5322Headers(message: String)
  case InvalidEntryInDKIMHeader(message: String)
  case BodyHashDoesNotMatch(message: String)
  case SignatureDoesNotMatch
  case InvalidDNSEntry(message: String)
  case UnexpectedError(message: String)
}

public enum DKIMRisks: Hashable, Equatable {
  case UsingLengthParameter  // only verified to a specific body length
  case UsingSHA1  // insecure hashing algorithm
  case SDIDNotEqualToSender  // third-party signature, From: Sender different to DKIM Domain
  case ImportantHeaderFieldNotSigned(name: String)  // only From: field required, but more fields are better else manipulation possible
  // Subject, Content-Type, Reply-To,... should be signed
}

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
  var version: UInt
  var algorithm: DKIMSignatureAlgorithm
  var signature: String
  var bodyHash: String
  var headerCanonicalization: DKIMCanonicalization  // optional, but default simple
  var bodyCanonicalization: DKIMCanonicalization  // optional, but default simple
  var sdid: String
  var signedHeaderFields: [String]
  var domainSelector: String
  var publicKeyQueryMethod: DKIMPublicKeyQueryMethod  // optional, but default dns/txt

  var auid: String?
  var bodyLength: UInt?
  var signatureTimestamp: Date?
  var signatureExpiration: String?
  var copiedHeaderFields: String?
}

public struct DMARCResult: Equatable {
  var entry: DMARCEntry
  var validDKIMIdentifierAlignment: Bool
}

public struct DMARCEntry: Equatable {
  var dkimAlignmentMode: AlignmentMode  // default relaxed
  // var SPFAlignmentMode : AlignmentMode // default relaxed
  //var failureReportingOptions:  FailureReportingOptions // default is AllFail
  var mailReceiverPolicy: MailReceiverPolicy  // required
  //var pct : Int // default 100, between 0 and 100
  //var reportFormats  : [String] // requested report formats
  //var reportInterval: Int // default 86400
  //var aggregateFeedbackAddresses: [String] // optional
  //var failureFeedbackAdresses: [String] // optional
  var subdomainMailReceiverPolicy: MailReceiverPolicy  // optional
  var version: DMARCVersion
}

public enum DMARCError: Error, Equatable {
  case TagValueListParsingError(message: String)
  case InvalidEntryInDMARCHeader(message: String)
  case InvalidDNSEntry(message: String)
  case InvalidURL(message: String)
  case UnexpectedError(message: String)
}
```

## Oracle Test Tool

### Setup

```
python3 -m pip install dkimpy
npm install -g mailauth
```

### Run

```
./Tools/gen_oracle_reports.sh ../../emails 50 > oracle_log.csv
./Tools/analyze_oracle_report.py oracle_log.csv
```
