import DKIMVerifier
import Foundation
import ArgumentParser

struct DKIMVerifierTool: ParsableCommand {
    @Argument() var email_path: String
    @Argument() var dns_path: String
    
    func run() {
        do {
        let email_raw = try String(contentsOf: URL(fileURLWithPath: email_path), encoding: .ascii)
        let dns_raw = try String(contentsOf: URL(fileURLWithPath: dns_path), encoding: .ascii)
        print(try DKIMVerifier.init(dnsLoopupTxtFunction: {(domain) in Optional(dns_raw) } ).verify(email_raw: email_raw))
        } catch {
            print("failure: \(error)")
        }
    }
}

DKIMVerifierTool.main()
