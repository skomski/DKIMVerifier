import ArgumentParser
import DKIMVerifier
import Foundation

struct DKIMVerifierTool: ParsableCommand {
  @Argument() var email_path: String
  //@Argument() var dns_path: String

  func run() {
    do {
      let email_raw = try String(contentsOf: URL(fileURLWithPath: email_path), encoding: .ascii)
      //let dns_raw = try String(contentsOf: URL(fileURLWithPath: dns_path), encoding: .ascii)
      print(
        try DKIMVerifier.verify(
          dnsLoopupTxtFunction: DKIMVerifier.queryDNSTXTEntry,
          email_raw: email_raw))
    } catch {
      print("failure: \(error)")
    }
  }
}

DKIMVerifierTool.main()
