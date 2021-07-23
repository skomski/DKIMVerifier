import Foundation

// typealias DNSLookupHandler = ([String: String]?) -> Void

// func queryDNSTXTEntry(domainName: String) -> String? {
//     var result: [String: String] = [:]
//     var recordHandler: DNSLookupHandler = {
//         (record) -> Void in
//         if (record != nil) {
//             for (k, v) in record! {
//                 result.updateValue(v, forKey: k)
//             }
//         }
//     }

//     let callback: DNSServiceQueryRecordReply = {
//         (sdRef, flags, interfaceIndex, errorCode, fullname, rrtype, rrclass, rdlen, rdata, ttl, context) -> Void in
//         guard let handlerPtr = context?.assumingMemoryBound(to: DNSLookupHandler.self) else {
//             return
//         }
//         let handler = handlerPtr.pointee
//         if (errorCode != kDNSServiceErr_NoError) {
//             return
//         }
//         guard let txtPtr = rdata?.assumingMemoryBound(to: UInt8.self) else {
//             return
//         }
//         let txt = String(cString: txtPtr.advanced(by: 1))
//         var record: [String: String] = [:]
//         record["result"] = txt
//         handler(record)
//     }

//     let serviceRef: UnsafeMutablePointer<DNSServiceRef?> = UnsafeMutablePointer.allocate(capacity: MemoryLayout<DNSServiceRef>.size)
//     let code = DNSServiceQueryRecord(serviceRef, kDNSServiceFlagsTimeout, 0, domainName, UInt16(kDNSServiceType_TXT), UInt16(kDNSServiceClass_IN), callback, &recordHandler)
//     if (code != kDNSServiceErr_NoError) {
//         return nil
//     }
//     DNSServiceProcessResult(serviceRef.pointee)
//     DNSServiceRefDeallocate(serviceRef.pointee)

//     return result["result"]
// }
