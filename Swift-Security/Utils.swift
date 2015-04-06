//
//  Utils.swift
//  Swift-Security
//
//  Created by Bouke Haarsma on 06-04-15.
//  Copyright (c) 2015 Bouke Haarsma. All rights reserved.
//

import Foundation


func sec(@autoclosure block: () -> OSStatus) -> Status {
    return Status(rawValue: block())
}


public enum Status {
    case Success
    case Param
    case ItemNotFound
    case AuthorizationDenied
    case Other(OSStatus)

    init(rawValue: OSStatus) {
        switch rawValue {
        case 0: self = .Success
        case -50: self = .Param
        case -25300: self = .ItemNotFound
        case -60005: self = .AuthorizationDenied
        default: self = .Other(rawValue)
        }
    }
}
extension Status: Printable {
    public var description: String {
        switch self {
        case .Success: return "Status.Success"
        case .Param: return "Status.Param"
        case .ItemNotFound: return "Status.ItemNotFound"
        case .AuthorizationDenied: return "Status.AuthorizationDenied"
        case .Other(let status): return "Status.Other(\(status))"
        }
    }
}


func group<R: SequenceType, G: Equatable>(elements: R, f: R.Generator.Element -> G?) -> [(G?, [R.Generator.Element])] {
    var groups: [G] = []
    var groupElements: [[R.Generator.Element]] = []
    var nilGroupElements: [R.Generator.Element] = []

    for element in elements {
        if let g = f(element) {
            switch find(groups, g) {
            case .Some(let idx):
                groupElements[idx].append(element)
            case .None:
                groups.append(g)
                groupElements.append([element])
            }
        } else {
            nilGroupElements.append(element)
        }
    }
    return [(nil, nilGroupElements)] + Array(zip(groups.map { Optional($0) }, groupElements))
}


func group<R: SequenceType, G: Equatable>(elements: R, f: R.Generator.Element -> G) -> [(G, [R.Generator.Element])] {
    var groups: [G] = []
    var groupElements: [[R.Generator.Element]] = []

    for element in elements {
        let g = f(element)
        switch find(groups, g) {
        case .Some(let idx):
            groupElements[idx].append(element)
        case .None:
            groups.append(g)
            groupElements.append([element])
        }
    }
    return Array(zip(groups, groupElements))
}
