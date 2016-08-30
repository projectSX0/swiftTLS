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
    
    internal init() {
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
    }
    
    public init(ca: String, ca_passwd: String?, cert: String, cert_passwd: String? , key: String, key_passwd: String?) throws {
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
        try load(file: cert, passwd: cert_passwd, to: tls_config_set_cert_mem)
        try load(file: ca, passwd: ca_passwd, to: tls_config_set_ca_mem)
        try load(file: key, passwd: key_passwd, to: tls_config_set_key_mem)
    }
    
    public init(ca_path: String, cert: String, cert_passwd: String? , key: String, key_passwd: String?) throws {
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
        try load(file: cert, passwd: cert_passwd, to: tls_config_set_cert_mem)
        try load(file: key, passwd: key_passwd, to: tls_config_set_key_mem)
        let c = ca_path.withCString{UnsafeMutablePointer<Int8>(mutating: $0)}
        if tls_config_set_ca_path(self.rawValue, c) < 0  {
            throw TLSError.unableToLoadFile(ca_path)
        }
    }
    
    private func load(file: String, passwd: String?, to fn: (OpaquePointer, UnsafePointer<UInt8>, size_t) -> Int32) throws
    {
        var s_ptr: UnsafeMutablePointer<size_t>!
        let pwd: UnsafeMutablePointer<Int8>? = passwd?.withCString {
                UnsafeMutablePointer(mutating: $0)
            }
        guard let addr = tls_load_file(file, s_ptr, pwd) else {
            throw TLSError.unableToLoadFile(file)
        }
        
        if fn(self.rawValue, addr, s_ptr.pointee) < 0 {
            throw TLSError.unableToLoadFile(file)
        }
    }
    
    public init(cert: String, cert_passwd: String?, key: String, key_passwd: String?) {
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
}

public extension TLSConfig {
    public func clearKeys() {
        tls_config_clear_keys(rawValue)
    }
}
