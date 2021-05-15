    import XCTest
    @testable import DKIMVerifier

    final class DKIMVerifierTests: XCTestCase {
        public var rfc6376_path : String = Bundle.module.path(forResource: "rfc6376", ofType: "msg")!
        public var rfc6376_signed_path : String = Bundle.module.path(forResource: "rfc6376.signed.rsa", ofType: "msg")!
        public var testkeydns_entry : String = Bundle.module.path(forResource: "testkeydnsentry", ofType: "txt")!
        public var spam_eml : String = Bundle.module.path(forResource: "spam", ofType: "eml")!
        
        func testSpamEmail() {
            do {
              let email_raw = try String(contentsOf: URL(fileURLWithPath: DKIMVerifierTests().spam_eml), encoding: .ascii)
              XCTAssertEqual(try DKIMVerifier().verify(email_raw: email_raw), true)
            } catch {
                XCTFail("spam email should verify: \(error)")
            }
        }
    }
