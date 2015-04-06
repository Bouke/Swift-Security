//
//  Policy.swift
//  Swift-Security
//
//  Created by Bouke Haarsma on 06-04-15.
//  Copyright (c) 2015 Bouke Haarsma. All rights reserved.
//

import Foundation


struct Policy {
    let ref: SecPolicy
    var type: PolicyType {
        let cfData = SecPolicyCopyProperties(ref)
        let data = cfData.takeUnretainedValue() as! [String: AnyObject]
        return PolicyType(rawValue: data[kSecPolicyOid.takeUnretainedValue() as! String] as! String)
    }
}
extension Policy: Printable {
    var description: String {
        return "Policy(type=\(type))"
    }
}


public enum PolicyType {
    case AppleX509Basic, AppleSSL, AppleSMIME, AppleEAP, AppleIPsec, AppleiChat, ApplePKINITClient, ApplePKINITServer, AppleCodeSigning, MacAppStoreReceipt, AppleIDValidation, AppleTimeStamping
    case Other(String)

    init(rawValue: String) {
        switch rawValue {
        case kSecPolicyAppleX509Basic.takeUnretainedValue() as! String: self = .AppleX509Basic
        case kSecPolicyAppleSSL.takeUnretainedValue() as! String: self = .AppleSSL
        case kSecPolicyAppleSMIME.takeUnretainedValue() as! String: self = .AppleSMIME
        case kSecPolicyAppleEAP.takeUnretainedValue() as! String: self = .AppleEAP
        case kSecPolicyAppleIPsec.takeUnretainedValue() as! String: self = .AppleIPsec
        case "1.2.840.113635.100.1.12": self = .AppleiChat
        case kSecPolicyApplePKINITClient.takeUnretainedValue() as! String: self = .ApplePKINITClient
        case kSecPolicyApplePKINITServer.takeUnretainedValue() as! String: self = .ApplePKINITServer
        case kSecPolicyAppleCodeSigning.takeUnretainedValue() as! String: self = .AppleCodeSigning
        case kSecPolicyMacAppStoreReceipt.takeUnretainedValue() as! String: self = .MacAppStoreReceipt
        case kSecPolicyAppleIDValidation.takeUnretainedValue() as! String: self = .AppleIDValidation
        case kSecPolicyAppleTimeStamping.takeUnretainedValue() as! String: self = .AppleTimeStamping
        default: self = .Other(rawValue)
        }
    }
}
extension PolicyType: Printable {
    public var description: String {
        switch self {
        case .AppleX509Basic: return "AppleX509Basic"
        case .AppleSSL: return "AppleSSL"
        case .AppleSMIME: return "AppleSMIME"
        case .AppleEAP: return "AppleEAP"
        case .AppleIPsec: return "AppleIPsec"
        case .AppleiChat: return "AppleiChat"
        case .ApplePKINITClient: return "ApplePKINITClient"
        case .ApplePKINITServer: return "ApplePKINITServer"
        case .AppleCodeSigning: return "AppleCodeSigning"
        case .MacAppStoreReceipt: return "MacAppStoreReceipt"
        case .AppleIDValidation: return "AppleIDValidation"
        case .AppleTimeStamping: return "AppleTimeStamping"
        case .Other(let other): return "Other(\(other))"
        }
    }
}
extension PolicyType: Equatable { }

public func == (lhs: PolicyType, rhs: PolicyType) -> Bool {
    switch (lhs, rhs) {
    case (.AppleX509Basic, .AppleX509Basic): return true
    case (.AppleSSL, .AppleSSL): return true
    case (.AppleSMIME, .AppleSMIME): return true
    case (.AppleEAP, .AppleEAP): return true
    case (.AppleIPsec, .AppleIPsec): return true
    case (.AppleiChat, .AppleiChat): return true
    case (.ApplePKINITClient, .ApplePKINITClient): return true
    case (.ApplePKINITServer, .ApplePKINITServer): return true
    case (.AppleCodeSigning, .AppleCodeSigning): return true
    case (.MacAppStoreReceipt, .MacAppStoreReceipt): return true
    case (.AppleIDValidation, .AppleIDValidation): return true
    case (.AppleTimeStamping, .AppleTimeStamping): return true
    case (.Other(let lhs), .Other(let rhs)): return true
    default: return false
    }
}
