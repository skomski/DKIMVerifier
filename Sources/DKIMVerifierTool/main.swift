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
      let result =
        DKIMVerifier.verifyDKIMSignatures(
          dnsLoopupTxtFunction: DKIMVerifier.queryDNSTXTEntry,
          email_raw: email_raw
        )
      switch result.status {
      case DKIMStatus.Valid:
        print("Valid")
      case DKIMStatus.Error(let error):
        print(error)
      case DKIMStatus.Insecure:
        var resultString = ""
        for signature in result.signatures {
          resultString += String(describing: signature.status) + " "
        }
        print(resultString)
      }
    } catch {
      print("failure: \(error)")
    }
  }
}

DKIMVerifierTool.main()
