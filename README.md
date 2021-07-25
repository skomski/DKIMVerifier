# DKIMVerifier (Swift)

### WIP!

## Features

* Verification of DKIM signatures (https://datatracker.ietf.org/doc/html/rfc6376)
* No boolean result: Additional detection of DKIM security pitfalls
* Query DMARC infos 

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