import ArgumentParser
import DKIMVerifier
import Foundation

struct DKIMVerifierTool: ParsableCommand {
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

  func run() {
    do {
      let email_raw: String
      if email_path != nil {
        email_raw = try String(contentsOf: URL(fileURLWithPath: email_path!), encoding: .ascii)
      } else {
        email_raw = String(bytes: FileHandle.standardInput.availableData, encoding: .ascii) ?? ""
      }
      if email_raw.isEmpty {
        print("failure: empty input")
        return
      }
      var dns_raw: String? = nil
      if dns_path != nil {
        dns_raw = try String(contentsOf: URL(fileURLWithPath: dns_path!), encoding: .ascii)
      }

      var dns_function = DKIMVerifier.queryDNSTXTEntry
      if dns_raw != nil {
        func custom_dns_function(domain: String) -> String? {
          return dns_raw
        }
        dns_function = custom_dns_function
      }

      let result =
        DKIMVerifier.verifyDKIMSignatures(
          dnsLoopupTxtFunction: dns_function,
          email_raw: email_raw, verifyDMARC: verifyDMARC
        )
      switch result.status {
      case DKIMStatus.Valid:
        print("Valid")
      case DKIMStatus.Insecure:
        print("Insecure")
      case DKIMStatus.Error(let error):
        print("Error")
        print("  \(error)")
      }

      if verbose {
        print("emailFrom: \(result.emailFromSender!)")
        print("extractedDomain: \(result.extractedDomainFromSender!)")
        print("\(result.signatures.count) signature(s)")
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
              "\(algorithm) \(keysize) sdid=\(signature.info!.sdid) auid=\(signature.info!.auid ?? "")"
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

    } catch {
      print("failure: \(error)")
    }
  }
}

DKIMVerifierTool.main()
