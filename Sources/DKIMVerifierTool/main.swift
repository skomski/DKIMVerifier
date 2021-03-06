import ArgumentParser
import DKIMVerifier
import DKIMVerifierToolBase
import Foundation

struct DKIMVerifierTool: ParsableCommand {
  @OptionGroup var options: DKIMVerifierToolBase.DKIMVerifierToolBaseArguments

  func run() {
    DKIMVerifierToolBase.baseRun(options: options)
  }
}

DKIMVerifierTool.main()
