//
//  Certificate.swift
//  Security
//
//  Created by Bouke Haarsma on 06-04-15.
//  Copyright (c) 2015 Bouke Haarsma. All rights reserved.
//

import Foundation
import Security

let SUBJECT_NAME = kSecOIDX509V1SubjectName.takeRetainedValue() as! String
let SEC_KEY_LABEL = kSecPropertyKeyLabel.takeUnretainedValue() as! String
let SEC_KEY_VALUE = kSecPropertyKeyValue.takeUnretainedValue() as! String


public func root_certs() -> [Certificate] {
    var result: Unmanaged<CFArray>?
    switch sec(SecTrustCopyAnchorCertificates(&result)) {
    case .Success:
        let certificates = map(result?.takeUnretainedValue() as! [SecCertificate]) { Certificate(ref: $0) }
        result?.release()
        return certificates
    default: abort()
    }
}


func cert_data(ref: SecCertificateRef, keys: [String]) -> [String: [String: String]] {
    var data = [String: [String: String]]()
    let contents = SecCertificateCopyValues(ref, keys, nil) as Unmanaged<CFDictionary>?
    if let contents = contents?.takeUnretainedValue() as? [String: NSDictionary] {
        for (key, value) in contents {
            data[key] = [:]
            if let contents2 = value[SEC_KEY_VALUE] as? [[String: String]] {
                for contents3 in contents2 {
                    if let key2 = contents3[SEC_KEY_LABEL] {
                        data[key]?[key2] = contents3[SEC_KEY_VALUE]
                    }
                }
            }
        }
    }
    return data
}


public struct Certificate {
    let ref: SecCertificateRef

    init(ref: SecCertificateRef) {
        self.ref = ref
    }

    public var commonName: String? {
        var cfName: Unmanaged<CFString>?
        SecCertificateCopyCommonName(self.ref, &cfName)
        var name = cfName?.takeUnretainedValue() as? String
        cfName?.release()

        if name == nil {
            let desc = SecCertificateCopyLongDescription(nil, self.ref, nil)
            name = desc.takeUnretainedValue() as? String
            desc.release()
        }

        return name
    }

    var subjectName: [String: String]? {
        return cert_data(ref, [SUBJECT_NAME])[SUBJECT_NAME]
    }

    public var subjectCountry: String? {
        return subjectName?["2.5.4.6"]
    }

    public func trustSettings(domain: TrustSettingsDomain) -> TrustSettings? {
        return TrustSettings(ref: ref, domain: domain)
    }
}
extension Certificate: Printable {
    public var description: String {
        return "Certificate(ref=\(ref))"
    }
}