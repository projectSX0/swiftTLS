//
//  TLSConfig.swift
//  swiftTLS
//
//  Created by yuuji on 8/25/16.
//
//

import Foundation
import libressl
import CKit

public typealias tls_config_t = OpaquePointer

public struct TLSConfig: OpaqueBridged {
    
    public var opaqueObj: OpaqueObject
    
    public init() {
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
    }
    
    public init?(rawValue: OpaquePointer) {
        opaqueObj = OpaqueObject(rawValue, free: tls_config_free)
    }
    
    public var protocols: TLSProtocols = TLSProtocols.default {
        didSet {
            tls_config_set_protocols(rawValue, UInt32(protocols.rawValue))
        }
    }
    
    public var keyFile: String? {
        didSet {
            if let file = keyFile {
                tls_config_set_key_file(rawValue, file)
            }
        }
    }
  
    public var keyMemLoca: ConvenientPointer<UInt8>? {
        didSet {
            if let memloca = keyMemLoca {
                tls_config_set_key_mem(rawValue, memloca.pointer, memloca.size)
            }
        }
    }
    
    public var certificateFile: String? {
        didSet {
            if let file = certificateFile {
                tls_config_set_ca_file(rawValue, file)
            }
        }
    }
    
    public var certificateSearchPath: String? {
        didSet {
            if let path = certificateSearchPath {
                tls_config_set_ca_path(rawValue, path)
            }
        }
    }
    
    public var certificateMemLoca: ConvenientPointer<UInt8>? {
        didSet {
            if let memloca = certificateMemLoca {
                tls_config_set_ca_mem(rawValue, memloca.pointer, memloca.size)
            }
        }
    }
}

public extension TLSConfig {
    public func clearKeys() {
        tls_config_clear_keys(rawValue)
    }
}

