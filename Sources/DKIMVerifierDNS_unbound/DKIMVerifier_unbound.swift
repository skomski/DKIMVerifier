import DKIMVerifier
import Foundation
import libunbound

public var rootKeyPath: String?

public func queryDNSTXTEntry(domainName: String) throws -> DNSResult {
  var result: DNSResult = DNSResult.init(result: String.init(), validatedWithDNSSEC: false)

  let ctx = ub_ctx_create()

  if ctx == nil {
    throw DKIMError.InvalidDNSEntry(message: "dns error: could not create unbound context")

  }

  if rootKeyPath == nil {
    throw DKIMError.InvalidDNSEntry(
      message: "dns error: root key not specified for unbound library")
  }

  /* read public keys for DNSSEC verification */
  if ub_ctx_add_ta_file(ctx, rootKeyPath!) != 0 {
    throw DKIMError.InvalidDNSEntry(
      message: "dns error: could not add root key for unbound library")
  }

  /* query for webserver */
  var ub_result: UnsafeMutablePointer<ub_result>?
  let retval = ub_resolve(
    ctx, domainName,
    16,  // kDNSServiceType_TXT,
    1 /* CLASS IN (internet) */, &ub_result)
  if retval != 0 {
    throw DKIMError.InvalidDNSEntry(message: "dns error: could not create unbound context")
  }

  if ub_result != nil {
    if ub_result!.pointee.havedata != 0 {
      var index = 0
      while ub_result!.pointee.data.advanced(by: index).pointee != nil {
        let data = Data(
          bytes: ub_result!.pointee.data.advanced(by: index).pointee!,
          count: Int(ub_result!.pointee.len.advanced(by: index).pointee))
        var position = 0
        while position < data.count {
          let lengthLeft: Int = Int(data[position])
          position += 1
          guard let partTxt = String(data: data[position..<position + lengthLeft], encoding: .utf8)
          else {
            throw DKIMError.InvalidDNSEntry(message: "invalid utf8")
          }
          result.result.append(partTxt)
          position += lengthLeft
        }
        index += 1
      }
    }

    if ub_result!.pointee.secure != 0 {
      result.validatedWithDNSSEC = true
    }
  }

  ub_resolve_free(ub_result)
  ub_ctx_delete(ctx)

  return result
}
