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

public typealias FileDescriptor = Int32

public struct TLSClient: TLSRole {
    public var opaqueObj: OpaqueObject
    public var config: TLSConfig!
}

public extension TLSClient {
    public init?(rawValue: OpaquePointer) {
        opaqueObj = OpaqueObject(rawValue, free: tls_free)
    }
    
    public init(with config: TLSConfig) throws {
        opaqueObj = OpaqueObject(tls_client(), free: tls_free)
        self.config = config
        try err(tls_configure(rawValue, config.rawValue))
    }
}
public extension TLSClient {
    
    public func connect(host server: String, port: String) throws {
        try err(tls_connect(rawValue, server, port))
    }
    
    public func connect(socket fd: FileDescriptor, server name: String) throws {
        try err(tls_connect_socket(rawValue, fd, name))
    }
    
    public func connect(read fd_r: FileDescriptor, write fd_w: FileDescriptor, for server: String) throws {
        try err(tls_connect_fds(rawValue, fd_r, fd_w, server))
    }
}
