//
//  TrustSettings.swift
//  Swift-Security
//
//  Created by Bouke Haarsma on 06-04-15.
//  Copyright (c) 2015 Bouke Haarsma. All rights reserved.
//

import Foundation


public enum TrustSettingsDomain {
    case User, Admin, System

    var rawValue: UInt32 {
        switch self {
        case .User: return UInt32(kSecTrustSettingsDomainUser)
        case .Admin: return UInt32(kSecTrustSettingsDomainAdmin)
        case .System: return UInt32(kSecTrustSettingsDomainSystem)
        }
    }
}


public enum TrustSettingsResult {
    case Invalid, TrustRoot, TrustAsRoot, Deny, Unspecified

    init(rawValue: Int) {
        switch rawValue {
        case kSecTrustSettingsResultInvalid: self = Invalid
        case kSecTrustSettingsResultTrustRoot: self = TrustRoot
        case kSecTrustSettingsResultTrustAsRoot: self = TrustAsRoot
        case kSecTrustSettingsResultDeny: self = Deny
        case kSecTrustSettingsResultUnspecified: self = Unspecified
        default: abort()
        }
    }

    var rawValue: Int {
        switch self {
        case Invalid: return kSecTrustSettingsResultInvalid
        case TrustRoot: return kSecTrustSettingsResultTrustRoot
        case TrustAsRoot: return kSecTrustSettingsResultTrustAsRoot
        case Deny: return kSecTrustSettingsResultDeny
        case Unspecified: return kSecTrustSettingsResultUnspecified
        }
    }
}
extension TrustSettingsResult: Printable {
    public var description: String {
        switch self {
        case .Invalid: return "Invalid"
        case .TrustRoot: return "TrustRoot"
        case .TrustAsRoot: return "TrustAsRoot"
        case .Deny: return "Deny"
        case .Unspecified: return "Unspecified"
        }
    }
}


public struct TrustSettings {
    let ref: SecCertificateRef
    let domain: TrustSettingsDomain

    private var settings: [(policy: Policy, result: TrustSettingsResult, data: [String: AnyObject])]

    init(ref: SecCertificateRef, domain: TrustSettingsDomain) {
        self.ref = ref
        self.domain = domain
        settings = []
        var result: Unmanaged<CFArray>?
        switch sec(SecTrustSettingsCopyTrustSettings(ref, domain.rawValue, &result)) {
        case .Success:
            for setting in result!.takeRetainedValue() as! [[String: AnyObject]] {
                if let policy = setting[kSecTrustSettingsPolicy] as! SecPolicy?, result = setting[kSecTrustSettingsResult] as? Int {
                    settings.append((policy: Policy(ref: policy), result: TrustSettingsResult(rawValue: result), data: setting))
                }
            }
            break
        default: break
        }
    }

    public subscript(key: PolicyType) -> TrustSettingsResult? {
        get {
            return first(settings.filter { $0.policy.type == key })?.result
        }
        set(newValue) {
            for (idx, var setting) in enumerate(settings) {
                if setting.policy.type == key {
                    setting.result = newValue!
                    setting.data[kSecTrustSettingsResult] = newValue!.rawValue
                    settings[idx] = (setting.policy, setting.result, setting.data)
                    return
                }
            }

            let policy = SecPolicyCreateWithProperties(key.rawValue, nil)
            settings.append(policy: Policy(ref: policy.takeUnretainedValue()), result: newValue!, data: [
                kSecTrustSettingsPolicy: policy.takeUnretainedValue(),
                kSecTrustSettingsResult: newValue!.rawValue,
                ])
        }
    }

    public func save() -> Status {
        return sec(SecTrustSettingsSetTrustSettings(ref, domain.rawValue, settings.map { $0.data }))
    }
}
extension TrustSettings: Printable {
    public var description: String {
        return "TrustSettings(\(settings.map { ($0.policy, $0.result) }))"
    }
}
