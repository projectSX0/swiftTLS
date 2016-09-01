//
//  TLSServer.swift
//  swiftTLS
//
//  Created by yuuji on 8/27/16.
//
//

import Foundation
import libressl
import CKit

public struct TLSServer: TLSRole {
    public var opaqueObj: OpaqueObject
    public var config: TLSConfig!
}

public extension TLSServer {
    
    public init(rawValue: OpaquePointer) {
        opaqueObj = OpaqueObject(rawValue, free: tls_free)
    }
    
    public init(with config: TLSConfig) throws {
        opaqueObj = OpaqueObject(tls_server(), free: tls_free)
        self.config = config
        try err(tls_configure(rawValue, config.rawValue))
    }
    
    public init(cert: String, cert_passwd: String? , key: String, key_passwd: String?) throws {
        opaqueObj = OpaqueObject(tls_server(), free: tls_free)
        self.config = try TLSConfig(cert: cert,
                                    cert_passwd: cert_passwd,
                                    key: key,
                                    key_passwd: key_passwd)
        try err(tls_configure(rawValue, config.rawValue))
    }
    
    public init(ca: String, ca_passwd: String?, cert: String, cert_passwd: String? , key: String, key_passwd: String?) throws {
        opaqueObj = OpaqueObject(tls_server(), free: tls_free)
        self.config = try TLSConfig(ca: ca,
                                    ca_passwd: ca_passwd,
                                    cert: cert,
                                    cert_passwd: cert_passwd,
                                    key: key,
                                    key_passwd: key_passwd)
        try err(tls_configure(rawValue, config.rawValue))
    }
    
    public init(ca_path: String, cert: String, cert_passwd: String? , key: String, key_passwd: String?) throws {
        opaqueObj = OpaqueObject(tls_server(), free: tls_free)
        self.config = try TLSConfig(ca_path: ca_path,
                                    cert: cert,
                                    cert_passwd: cert_passwd,
                                    key: key,
                                    key_passwd: key_passwd)
        try err(tls_configure(rawValue, config.rawValue))
    }
    
}

public extension TLSServer {
    public func accept(socket: Int32) throws -> TLSClient {
        var client_raw: OpaquePointer?
        try err(tls_accept_socket(rawValue,
                          mutablePointer(of: &client_raw),
                          socket))
        return TLSClient(rawValue: client_raw!)
    }
    
    public func accept(read fd_r: Int32, write fd_w: Int32) throws -> TLSClient {
        var client_raw: OpaquePointer?
        try err(tls_accept_fds(rawValue,
                               mutablePointer(of: &client_raw),
                               fd_r, fd_w))
        return TLSClient(rawValue: client_raw!)
    }
}

