# DKIMVerifier (Swift)

### WIP!

## Features

* Verification of DKIM signatures (https://datatracker.ietf.org/doc/html/rfc6376)
* No boolean result: Additional detection of DKIM security pitfalls
* DMARC Alignment Policy Verification

## API

###  DKIM Verification

```swift
DKIMVerifier.verify(dnsLoopupTxtFunction: @escaping (String) throws -> String?, email_raw: String)
-> DKIMResult
```

Arguments:
* dnsLookupTxtFunction: should return txt value for specific domain
* email_raw: RFC822 Message as raw string

Result:
```swift
public enum DKIMStatus: Equatable {
  case Valid // valid
  case Valid_Insecure(Set<DKIMRisks>) // valid but possible risks
  case Invalid(DKIMError) // invalid signature
  case NoSignature // no dkim signature detected
  case Error(DKIMError) // error during the verification process
}

public enum DKIMRisks: Equatable {
  case UsingLengthParameter  // only verified to a specific body length
  case UsingSHA1  // insecure hashing algorithm
  case SDIDNotEqualToSender  // third-party signature, From: Sender different to DKIM Domain
  case FewHeaderFieldsSigned  // only From: field required, but more fields are better else manipulation possible
  // Subject, Content-Type, Reply-To,... should be signed
  // more coming...
}

public enum DKIMError: Error, Equatable {
  case TagValueListParsingError(message: String)
  case RFC822MessageParsingError(message: String)
  case InvalidRFC822Headers(message: String)
  case InvalidEntryInDKIMHeader(message: String)
  case BodyHashDoesNotMatch(message: String)
  case InvalidDNSEntry(message: String)
  case UnexpectedError(message: String)
}

public struct DKIMInfo: Equatable {
  var version: String?
  var sdid: String?
  var auid: String?
  var from_sender: String?
}

public struct DKIMResult: Equatable {
  var status: DKIMStatus
  var info: DKIMInfo?
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
