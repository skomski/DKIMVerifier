import ArgumentParser
import DKIMVerifier
import DKIMVerifierDNS_dnssd
import DKIMVerifierToolBase
import Foundation

#if canImport(dnssd)

struct DKIMVerifierTool_dnssd: ParsableCommand {
  @OptionGroup var options: DKIMVerifierToolBase.DKIMVerifierToolBaseArguments

  func run() {
    dnsFunction = DKIMVerifierDNS_dnssd.queryDNSTXTEntry
    DKIMVerifierToolBase.baseRun(options: options)
  }
}

DKIMVerifierTool_dnssd.main()

#endif
