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
    
    public init?(rawValue: OpaquePointer) {
        opaqueObj = OpaqueObject(rawValue, free: {tls_free($0)})
    }
    
    public init?(with config: TLSConfig) throws {
        opaqueObj = OpaqueObject(tls_server(), free: {tls_free($0)})
        self.config = config
        try err(tls_configure(rawValue, config.rawValue))
    }
}
public extension TLSServer {
    public func accept(socket: FileDescriptor) throws -> TLSClient {
        var client_raw: OpaquePointer?
        try err(tls_accept_socket(rawValue,
                          mutablePointer(of: &client_raw),
                          socket))
        return TLSClient(rawValue: client_raw!)!
    }
    
    public func accept(read fd_r: FileDescriptor, write fd_w: FileDescriptor) throws -> TLSClient {
        var client_raw: OpaquePointer?
        try err(tls_accept_fds(rawValue,
                               mutablePointer(of: &client_raw),
                               fd_r, fd_w))
        return TLSClient(rawValue: client_raw!)!
    }
}

