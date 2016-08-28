//
//  TLSProtocols.swift
//  swiftTLS
//
//  Created by yuuji on 8/25/16.
//
//

import Foundation
import libressl

public struct TLSProtocols: OptionSet {
    public var rawValue: Int32
    public typealias RawValue = Int32
    
    public static let v1_0 = TLSProtocols(rawValue: TLS_PROTOCOL_TLSv1_0)
    public static let v1_1 = TLSProtocols(rawValue: TLS_PROTOCOL_TLSv1_1)
    public static let v1_2 = TLSProtocols(rawValue: TLS_PROTOCOL_TLSv1_2)
    public static let `default` = TLSProtocols(rawValue: TLS_PROTOCOLS_DEFAULT)
    public static let secure = TLSProtocols(rawValue: TLS_PROTOCOL_TLSv1_2)
    public static let v1 = TLSProtocols(rawValue: TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1 | TLS_PROTOCOL_TLSv1_2)
    public static let all = v1
    
    public init(rawValue: Int32) {
        self.rawValue = rawValue
    }
}
