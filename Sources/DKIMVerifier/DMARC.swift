import Foundation

enum AlignmentMode {
  case Relaxed
  case Strict
}

enum FailureReportingOptions {
  case AllFail
  case AnyFail
  case DKIMFailure
  case SPFFailure
}

enum MailReceiverPolicy {
  case None
  case Quarantine
  case Reject
}

enum DMARCVersion {
  case One
}

public struct DMARCEntry {
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
  case UnexpectedError(message: String)
}

public enum DMARCStatus: Equatable {
  case Valid
  case Error(DMARCError)
}

public struct DMARCResult {
  var status: DMARCStatus
  var entry: DMARCEntry
}

public func queryDMARC(
  dnsLoopupTxtFunction: @escaping (String) throws -> String?, domain: String
) throws -> DMARCEntry {
  let dmarcDomain = "_dmarc." + domain
  let txtEntry: String?
  do {
    txtEntry = try dnsLoopupTxtFunction(dmarcDomain)
  } catch {
    throw DMARCError.UnexpectedError(message: error.localizedDescription)
  }

  guard txtEntry != nil else {
    throw DMARCError.InvalidDNSEntry(message: "DNS Entry is empty for domain: \(dmarcDomain)")
  }

  let dmarcFields = try parseTagValueList(raw_list: txtEntry!)

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

  return dmarcEntry
}
