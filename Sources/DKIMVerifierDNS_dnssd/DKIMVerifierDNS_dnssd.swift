import DKIMVerifier
import Foundation

#if canImport(dnssd)

import dnssd

struct InternalDNSResult {
  var error: DKIMError?
  var entry: String
  var validatedWithDNSSEC: Bool
}

public func queryDNSTXTEntry(domainName: String) throws -> DNSResult {
  var result: InternalDNSResult = InternalDNSResult.init(
    error: nil, entry: String.init(), validatedWithDNSSEC: false)

  let callback: DNSServiceQueryRecordReply = {
    (
      _, flags, _, errorCode, _, _, _, rdlen, rdata, _,
      context
    )
      -> Void in
    guard let resultPtr = context?.assumingMemoryBound(to: InternalDNSResult.self) else {
      return
    }
    if errorCode != kDNSServiceErr_NoError {
      resultPtr.pointee.error = DKIMError.InvalidDNSEntry(message: "dns error")
      return
    }
    guard let txtPtr = rdata?.bindMemory(to: CChar.self, capacity: Int(rdlen)) else {
      return
    }
    let data = Data(bytes: txtPtr, count: Int(rdlen))

    var position = 0
    while position < data.count {
      let lengthLeft: Int = Int(data[position])
      position += 1
      guard let partTxt = String(data: data[position..<position + lengthLeft], encoding: .utf8)
      else {
        resultPtr.pointee.error = DKIMError.InvalidDNSEntry(message: "invalid utf8")
        return
      }
      resultPtr.pointee.entry.append(partTxt)
      position += lengthLeft
    }

    resultPtr.pointee.validatedWithDNSSEC = (flags & kDNSServiceFlagsSecure) != 0
  }

  let serviceRef: UnsafeMutablePointer<DNSServiceRef?> = UnsafeMutablePointer.allocate(
    capacity: MemoryLayout<DNSServiceRef>.size)
  let code = DNSServiceQueryRecord(
    serviceRef,
    kDNSServiceFlagsEnableDNSSEC | kDNSServiceFlagsTimeout | kDNSServiceFlagsLongLivedQuery, 0,
    domainName, UInt16(kDNSServiceType_TXT),
    UInt16(kDNSServiceClass_IN), callback, &result)
  if code != kDNSServiceErr_NoError {
    throw DKIMError.InvalidDNSEntry(message: "dns error")
  }
  DNSServiceProcessResult(serviceRef.pointee)
  DNSServiceRefDeallocate(serviceRef.pointee)

  if result.error != nil {
    throw result.error!
  }
  return DNSResult.init(result: result.entry, validatedWithDNSSEC: result.validatedWithDNSSEC)
}

#endif
