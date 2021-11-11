import ArgumentParser
import DKIMVerifier
import Foundation

public var dnsFunction: DNSLookupFunctionType?

public struct DKIMVerifierToolBaseArguments: ParsableArguments {
  public init() {}

  @Flag(help: "Additional get DMARC information and check DKIM alignment")
  var verifyDMARC = false

  @Flag(name: .long, help: "Display extra information while processing.")
  var verbose = false

  @Option(
    help: ArgumentHelp(
      "The input dns file.",
      valueName: "file"))
  var dns_path: String?

  @Argument(
    help: ArgumentHelp(
      "The input eml file.",
      discussion: "If no input file is provided, the tool reads from stdin.",
      valueName: "file"))
  var email_path: String?
}

func printDMARCInfo(result: DKIMResult) {
  if result.dmarcResult == nil {
    print("DMARC")
    print("  Not checked")
    return
  }
  print("DMARC (dnssec=\(result.dmarcResult!.validatedWithDNSSEC))")
  print("  dkimAlignmentResult: \(result.dmarcResult!.status)")
  print("  foundSenderDomain: \(result.dmarcResult!.fromSenderDomain)")
  print("  validDKIMDomains: \(result.dmarcResult!.validDKIMDomains)")
  print("  foundPolicyDomain: \(result.dmarcResult!.foundPolicyDomain ?? "")")
  print("  validDomain: \(result.dmarcResult!.validDomain ?? "")")
  if result.dmarcResult!.entry != nil {
    print("  dkimAlignmentMode('adkim'): \(result.dmarcResult!.entry!.dkimAlignmentMode)")
    print("  mailReceiverPolicy('p'): \(result.dmarcResult!.entry!.mailReceiverPolicy)")
    print(
      "  subdomainMailReceiverPolicy('sp'): \(result.dmarcResult!.entry!.subdomainMailReceiverPolicy)"
    )
  }
}

func printVerboseInfo(result: DKIMResult) {
  print("DKIM (Verbose)")
  print(" emailFrom: \(result.emailFromSender ?? "missing")")
  print(" extractedDomain: \(result.extractedDomainFromSender ?? "missing")")
  print(" \(result.signatures.count) signature(s)")
  for signature in result.signatures {
    let status: String
    var info: String = "no info"
    if signature.info != nil {
      let algorithm = signature.info!.algorithm
      let keysize: String
      if signature.info!.rsaKeySizeInBits != nil {
        keysize = String(signature.info!.rsaKeySizeInBits!)
      } else {
        keysize = "unsupported"
      }
      info =
        "\(algorithm) \(keysize) sdid=\(signature.info!.sdid) auid=\(signature.info!.auid ?? "") dnssec=\(signature.validatedWithDNSSEC)"
    }
    switch signature.status {
    case DKIMSignatureStatus.Valid:
      status = "Valid"
      print("  \(status) (\(info))")
    case DKIMSignatureStatus.Insecure(let risks):
      status = "Insecure"
      print("  \(status) (\(info))")
      for risk in risks {
        print("    \(String(describing: risk))")
      }
    case DKIMSignatureStatus.Error(let error):
      status = "\(error)"
      print("  Error\n    \(status) (\(info))")
    }
  }
}

public func baseRun(options: DKIMVerifierToolBaseArguments) {
  do {

    let email_raw: String
    if options.email_path != nil {
      email_raw = try String(
        contentsOf: URL(fileURLWithPath: options.email_path!), encoding: .ascii)
    } else {
      email_raw = String(bytes: FileHandle.standardInput.availableData, encoding: .ascii) ?? ""
    }
    if email_raw.isEmpty {
      print("failure: empty input")
      return
    }
    var dns_raw: String?
    if options.dns_path != nil {
      dns_raw = try String(contentsOf: URL(fileURLWithPath: options.dns_path!), encoding: .ascii)
    }

    if dns_raw == nil && dnsFunction == nil {
      print("failure: no dns support compiled in. You need to provide a dns file")
      return
    }

    let dns_function: DNSLookupFunctionType
    if dns_raw != nil {
      func custom_dns_function(domain: String) -> DNSResult {
        return DNSResult.init(result: dns_raw!, validatedWithDNSSEC: true)
      }
      dns_function = custom_dns_function
    } else {
      dns_function = dnsFunction!
    }

    let result =
      DKIMVerifier.verifyDKIMSignatures(
        dnsLoopupTxtFunction: dns_function,
        email_raw: email_raw, verifyDMARC: options.verifyDMARC
      )

    print("DKIM")
    switch result.status {
    case DKIMStatus.Valid:
      print("Valid")
    case DKIMStatus.Insecure:
      print("Insecure")
    case DKIMStatus.Error(let error):
      print("Error")
      print("  \(error)")
    }

    if options.verifyDMARC {
      printDMARCInfo(result: result)
    }

    if options.verbose {
      printVerboseInfo(result: result)
    }
  } catch {
    print("failure: \(error)")
  }
}
