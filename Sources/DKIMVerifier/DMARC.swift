import Foundation

public enum AlignmentMode {
  case Relaxed
  case Strict
}

public enum FailureReportingOptions {
  case AllFail
  case AnyFail
  case DKIMFailure
  case SPFFailure
}

public enum MailReceiverPolicy {
  case None
  case Quarantine
  case Reject
}

public enum DMARCVersion {
  case One
}

public struct DMARCEntry: Equatable {
  public var dkimAlignmentMode: AlignmentMode  // default relaxed
  // var SPFAlignmentMode : AlignmentMode // default relaxed
  // var failureReportingOptions:  FailureReportingOptions // default is AllFail
  public var mailReceiverPolicy: MailReceiverPolicy  // required
  // var pct : Int // default 100, between 0 and 100
  // var reportFormats  : [String] // requested report formats
  // var reportInterval: Int // default 86400
  // var aggregateFeedbackAddresses: [String] // optional
  // var failureFeedbackAdresses: [String] // optional
  public var subdomainMailReceiverPolicy: MailReceiverPolicy  // optional
  public var version: DMARCVersion
}

enum DMARCTagNames: String {
  case Version = "v"  // required
  case MailReceiverPolicy = "p"  // required
  case SubdomainMailReceiverPolicy = "sp"  // optional
  case DKIMAlignmentMode = "adkim"  // optional
}

public enum DMARCError: Error, Equatable {
  case TagValueListParsingError(message: String)
  case InvalidEntryInDMARCHeader(message: String)
  case InvalidDNSEntry(message: String)
  case InvalidURL(message: String)
  case InvalidDKIMIdentifierAlignment
  case UnexpectedError(message: String)
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

internal func checkDMARC(
  dnsLookupTxtFunction: @escaping DNSLookupFunctionType, fromSenderDomain: String,
  validDKIMDomains: [String]
) -> DMARCResult {
  // 1. check subdomain dmarc entry
  let subdomainDmarc = "_dmarc." + fromSenderDomain
  var dmarcResult = DMARCResult.init(
    status: DMARCStatus.Error(DMARCError.UnexpectedError(message: "Not set")),
    fromSenderDomain: fromSenderDomain, validDKIMDomains: validDKIMDomains,
    validatedWithDNSSEC: false, entry: nil, foundPolicyDomain: nil, validDomain: nil)

  do {
    (dmarcResult.entry, dmarcResult.validatedWithDNSSEC) = try queryDMARC(
      dnsLookupTxtFunction: dnsLookupTxtFunction, domain: subdomainDmarc)
    dmarcResult.foundPolicyDomain = subdomainDmarc
  } catch {
    // 1.1. check organizational dmarc entry
    let splittedDomain = fromSenderDomain.split(separator: ".")
    guard splittedDomain.count > 1 else {
      dmarcResult.status = DMARCStatus.Error(
        DMARCError.InvalidURL(message: "root domain extraction error"))
      return dmarcResult
    }
    let orgDomainDMARC =
      splittedDomain[splittedDomain.endIndex - 2] + "."
      + splittedDomain[splittedDomain.endIndex - 1]

    do {
      (dmarcResult.entry, dmarcResult.validatedWithDNSSEC) = try queryDMARC(
        dnsLookupTxtFunction: dnsLookupTxtFunction, domain: String(orgDomainDMARC))
    } catch let error as DMARCError {
      dmarcResult.status = DMARCStatus.Error(error)
      return dmarcResult
    } catch {
      dmarcResult.status = DMARCStatus.Error(DMARCError.UnexpectedError(message: "\(error)"))
      return dmarcResult
    }

    dmarcResult.foundPolicyDomain = String(orgDomainDMARC)
  }

  // 3. check strict or relaxed alignment for valid dkim domains

  dmarcResult.status = DMARCStatus.Error(DMARCError.InvalidDKIMIdentifierAlignment)

  for domain in validDKIMDomains {
    if dmarcResult.entry!.dkimAlignmentMode == AlignmentMode.Relaxed {
      if fromSenderDomain.hasSuffix(domain) {
        dmarcResult.status = DMARCStatus.validDKIMIdentifierAlignment
        dmarcResult.validDomain = domain
        break
      }
    } else if dmarcResult.entry!.dkimAlignmentMode == AlignmentMode.Strict {
      if domain == fromSenderDomain {
        dmarcResult.status = DMARCStatus.validDKIMIdentifierAlignment
        dmarcResult.validDomain = domain
        break
      }
    }
  }

  return dmarcResult
}

internal func queryDMARC(
  dnsLookupTxtFunction: @escaping DNSLookupFunctionType, domain: String
) throws -> (DMARCEntry, Bool) {
  let dmarcDomain = "_dmarc." + domain
  let txtEntry: String
  let validatedWithDNSSEC: Bool
  do {
    let dnsResult = try dnsLookupTxtFunction(dmarcDomain)
    txtEntry = dnsResult.result
    validatedWithDNSSEC = dnsResult.validatedWithDNSSEC
  } catch {
    throw DMARCError.UnexpectedError(message: error.localizedDescription)
  }

  guard !txtEntry.isEmpty else {
    throw DMARCError.InvalidDNSEntry(message: "DNS Entry is empty for domain: \(dmarcDomain)")
  }

  print(txtEntry)

  let dmarcFields = try parseTagValueList(raw_list: txtEntry)

  guard let dmarcVersionString: String = dmarcFields[DMARCTagNames.Version.rawValue] else {
    throw DMARCError.InvalidEntryInDMARCHeader(message: "no version provided ('v')")
  }

  guard dmarcVersionString == "DMARC1" else {
    throw DMARCError.InvalidEntryInDMARCHeader(
      message: "invalid version provided \(dmarcVersionString) ('v')")
  }

  var dkimAlignmentMode: AlignmentMode = AlignmentMode.Relaxed

  if let dkimAlignmentModeString = dmarcFields[DMARCTagNames.DKIMAlignmentMode.rawValue] {
    if dkimAlignmentModeString == "r" {
      dkimAlignmentMode = AlignmentMode.Relaxed
    } else if dkimAlignmentModeString == "s" {
      dkimAlignmentMode = AlignmentMode.Strict
    } else {
      throw DMARCError.InvalidEntryInDMARCHeader(
        message: "invalid dkim alignment mode value provided")
    }
  }

  let mailReceiverPolicy: MailReceiverPolicy

  guard let mailReceiverPolicyString = dmarcFields[DMARCTagNames.MailReceiverPolicy.rawValue] else {
    throw DMARCError.InvalidEntryInDMARCHeader(message: "no mail receiver policy value provided")
  }

  if mailReceiverPolicyString == "none" {
    mailReceiverPolicy = MailReceiverPolicy.None
  } else if mailReceiverPolicyString == "quarantine" {
    mailReceiverPolicy = MailReceiverPolicy.Quarantine
  } else if mailReceiverPolicyString == "reject" {
    mailReceiverPolicy = MailReceiverPolicy.Reject
  } else {
    throw DMARCError.InvalidEntryInDMARCHeader(
      message: "invalid mail receiver policy value provided")
  }

  var subdomainMailReceiverPolicy: MailReceiverPolicy = mailReceiverPolicy

  if let subdomainMailReceiverPolicyString = dmarcFields[
    DMARCTagNames.SubdomainMailReceiverPolicy.rawValue]
  {
    if subdomainMailReceiverPolicyString == "none" {
      subdomainMailReceiverPolicy = MailReceiverPolicy.None
    } else if subdomainMailReceiverPolicyString == "quarantine" {
      subdomainMailReceiverPolicy = MailReceiverPolicy.Quarantine
    } else if subdomainMailReceiverPolicyString == "reject" {
      subdomainMailReceiverPolicy = MailReceiverPolicy.Reject
    } else {
      throw DMARCError.InvalidEntryInDMARCHeader(
        message: "invalid subdomain mail receiver policy value provided")
    }
  }

  let dmarcEntry = DMARCEntry.init(
    dkimAlignmentMode: dkimAlignmentMode, mailReceiverPolicy: mailReceiverPolicy,
    subdomainMailReceiverPolicy: subdomainMailReceiverPolicy, version: DMARCVersion.One)

  return (dmarcEntry, validatedWithDNSSEC)
}
