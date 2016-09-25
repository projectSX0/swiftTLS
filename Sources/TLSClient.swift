//
//  TLSClient.swift
//  swiftTLS
//
//  Created by yuuji on 8/27/16.
//
//

import Foundation
import libressl
import CKit

public struct TLSClient: TLSRole {
    public var opaqueObj: OpaqueObject
    public var config: TLSConfig!
}

public extension TLSClient {
    
    public init(rawValue: OpaquePointer) {
        opaqueObj = OpaqueObject(rawValue, free: tls_free)
    }
    
    public init(with config: TLSConfig) throws {
        opaqueObj = OpaqueObject(tls_client(), free: tls_free)
        self.config = config
        try err(tls_configure(rawValue, config.rawValue))
    }
    
    public static func insecureClient() -> TLSClient {
        return try! TLSClient(with: TLSConfig.insecureClientConf())
    }
    
    public static func securedClient() -> TLSClient {
        return try! TLSClient(with: TLSConfig())
    }
}

public extension TLSClient {
    
    public func connect(host server: String, port: String) throws {
        try err(tls_connect(rawValue, server, port))
    }
    
    public func connect(socket fd: Int32, server name: String) throws {
        try err(tls_connect_socket(rawValue, fd, name))
    }
    
    public func connect(read fd_r: Int32, write fd_w: Int32, for server: String) throws {
        try err(tls_connect_fds(rawValue, fd_r, fd_w, server))
    }
}
