import ArgumentParser
import DKIMVerifier
import DKIMVerifierDNS_unbound
import DKIMVerifierToolBase
import Foundation

struct DKIMVerifierTool_unbound: ParsableCommand {
  @OptionGroup var options: DKIMVerifierToolBase.DKIMVerifierToolBaseArguments

  @Option(
    help: ArgumentHelp(
      "The input root key file for DNSSEC.",
      valueName: "file"))
  var root_key_path: String

  func run() {
    dnsFunction = DKIMVerifierDNS_unbound.queryDNSTXTEntry
    rootKeyPath = root_key_path
    DKIMVerifierToolBase.baseRun(options: options)
  }
}

DKIMVerifierTool_unbound.main()
