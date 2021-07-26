import Foundation

#if os(macOS)  || os(iOS) || os(watchOS) || os(tvOS)

import dnssd

struct DNSResult {
  var error: DKIMError?
  var entry: String
}

public func queryDNSTXTEntry(domainName: String) throws -> String? {
  var result: DNSResult = DNSResult.init(error: nil, entry: String.init())

  let callback: DNSServiceQueryRecordReply = {
    (sdRef, flags, interfaceIndex, errorCode, fullname, rrtype, rrclass, rdlen, rdata, ttl, context)
      -> Void in
    guard let resultPtr = context?.assumingMemoryBound(to: DNSResult.self) else {
      return
    }
    if errorCode != kDNSServiceErr_NoError {
      resultPtr.pointee.error = DKIMError.invalidDNSEntry(message: "dns error")
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
        resultPtr.pointee.error = DKIMError.invalidDNSEntry(message: "invalid utf8")
        return
      }
      resultPtr.pointee.entry.append(partTxt)
      position += lengthLeft
    }
  }

  let serviceRef: UnsafeMutablePointer<DNSServiceRef?> = UnsafeMutablePointer.allocate(
    capacity: MemoryLayout<DNSServiceRef>.size)
  let code = DNSServiceQueryRecord(
    serviceRef, kDNSServiceFlagsTimeout, 0, domainName, UInt16(kDNSServiceType_TXT),
    UInt16(kDNSServiceClass_IN), callback, &result)
  if code != kDNSServiceErr_NoError {
    return nil
  }
  DNSServiceProcessResult(serviceRef.pointee)
  DNSServiceRefDeallocate(serviceRef.pointee)

  if result.error != nil {
    throw result.error!
  }
  return result.entry
}

#else

public func queryDNSTXTEntry(domainName: String) throws -> String? {
  return nil
}

#endif