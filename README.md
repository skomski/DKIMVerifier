# DKIMVerifier 0.1

[![build_and_test](https://github.com/skomski/DKIMVerifier/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/skomski/DKIMVerifier/actions/workflows/build_and_test.yml)

## Features

* Verification of DKIM signatures (https://datatracker.ietf.org/doc/html/rfc6376)
* No boolean result: Additional detection of DKIM security pitfalls
  * DKIM has user-configurable parameters that can make a valid DKIM signature pretty useless and this library strives to point out this misconfigured signatures
  * More info: https://github.com/skomski/DKIMVerifier/issues/10
* DMARC Alignment Policy Verification
  * additionally checks if the DMARC DKIM Alignment policy is correct for valid DKIM signatures
* Supports DNSSEC via libunbound (and in theory with dnssd)
* Includes a command line tool: DKIMVerifierTool with extensive output

## API

###  DKIM Verification

```swift
public func verifyDKIMSignatures(
  dnsLoopupTxtFunction: @escaping DNSLookupFunctionType,
  emailRaw: String,
  verifyDMARCAlignment: Bool = false
)
  -> DKIMResult
```

Arguments:
* dnsLookupTxtFunction: should return txt value for specific domain
* emailRaw: RFC5322 Message as raw string
* verifyDMARCAlignment: additional verify DMARC DKIM Alignment for valid signatures (default: false)

Result:
* status: an overall status, Valid or Insecure if any of the dkim signatures in the mail returned this result
* signatures: the individual signature results, good to check for DKIM Risks if the overall result is only Valid_Insecure
* emailFromSender: the extracted email from the From: mail header field
* extractedDomainFromSender: the extracted domain from the From: mail header field, used for the DKIM SDID and DMARC alignment checks 
* DMARCResult: the dmarc info and alignment check info if requested via verifyDMARCAlignment

```swift
public struct DKIMResult: Equatable {
  public var status: DKIMStatus
  public var signatures: [DKIMSignatureResult]

  public var emailFromSender: String?
  public var extractedDomainFromSender: String?
  public var extractedDomainFromSenderIdnaEncoded: String?

  public var dmarcResult: DMARCResult?
}

public struct DKIMSignatureResult: Equatable {
  public var status: DKIMSignatureStatus
  public var info: DKIMSignatureInfo?
  public var dnsInfo: DKIMSignatureDNSInfo?
  public var validatedWithDNSSEC: Bool = false
}

public enum DKIMSignatureStatus: Equatable {
  case Valid
  case Insecure(Set<DKIMRisks>)
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

public enum DMARCStatus: Equatable {
  case validDKIMIdentifierAlignment
  case Error(DMARCError)
}

public struct DMARCResult: Equatable {
  public var status: DMARCStatus
  public var fromSenderDomain: String
  public var validDKIMDomains: [String]
  public var validatedWithDNSSEC: Bool

  public var entry: DMARCEntry?
  public var foundPolicyDomain: String?
  public var validDomain: String?
}
```
