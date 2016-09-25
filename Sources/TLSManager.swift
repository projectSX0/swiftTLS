//
//  TLS.swift
//  swiftTLS
//
//  Created by yuuji on 8/25/16.
//
//

import Foundation
import libressl

public struct TLSManager {
    
    static var `default`: TLSManager?
    
    /// return the error string of last error of `tls`
    ///
    /// - parameter tls: The TLS context
    ///
    /// - returns: error string of last error of `tls`
    @inline(__always)
    public static func error(of tls: TLSServer) -> String {
        return error(of: tls)
    }
    
    
    /// return the error string of last error of `tls`
    ///
    /// - parameter tls: The TLS context
    ///
    /// - returns: error string of last error of `tls`
    @inline(__always)
    public static func error(of tls: TLSClient) -> String {
        return error(of: tls)
    }
    
    @inline(__always)
    internal static func error<T: TLSRole>(of tls: T) -> String {
        return String(cString: tls_error(tls.rawValue))
    }
    
    internal init() {
        _ = tls_init()
    }
}

