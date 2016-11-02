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
    
    public static func insecureClientConf() -> TLSConfig {
        if TLSManager.default == nil {
            TLSManager.default = TLSManager()
        }
        
        var config = TLSConfig()
        tls_config_insecure_noverifycert(config.rawValue)
        tls_config_insecure_noverifyname(config.rawValue)
        return config
    }
    
    public init(cert: UnsafePointer<Int8>, cert_passwd: String? , key: UnsafePointer<Int8>, key_passwd: String?) throws {
        
        if TLSManager.default == nil {
            TLSManager.default = TLSManager()
        }
        
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
        self.protocols = .secure
        
        _ = try load1(file: cert, passwd: cert_passwd, to: tls_config_set_cert_mem)
        _ = try load1(file: key, passwd: key_passwd, to: tls_config_set_key_mem)
    }
    
    
    public init(ca: UnsafePointer<Int8>, ca_passwd: String?, cert: UnsafePointer<Int8>, cert_passwd: String? , key: UnsafePointer<Int8>, key_passwd: String?) throws {
        
        if TLSManager.default == nil {
            TLSManager.default = TLSManager()
        }
        
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
        
        self.protocols = .all
        
        try load1(file: cert, passwd: cert_passwd, to: tls_config_set_cert_mem)
        try load1(file: ca, passwd: ca_passwd, to: tls_config_set_ca_mem)
        try load1(file: key, passwd: key_passwd, to: tls_config_set_key_mem)
    }
    
    public init(ca_path: UnsafePointer<Int8>?, cert: UnsafePointer<Int8>, cert_passwd: String? , key: UnsafePointer<Int8>, key_passwd: String?) throws {
        opaqueObj = OpaqueObject(tls_config_new(), free: tls_config_free)
        
        if TLSManager.default == nil {
            TLSManager.default = TLSManager()
        }
        
        self.protocols = .secure
        
        try load1(file: cert, passwd: cert_passwd, to: tls_config_set_cert_mem)
        try load1(file: key, passwd: key_passwd, to: tls_config_set_key_mem)
        if let _ = ca_path {
            if tls_config_set_ca_path(self.rawValue, ca_path) < 0  {
                throw TLSError.unableToLoadFile(String(cString: ca_path!))
            }
        }
    }
    
    @inline(__always)
    private func load(file: String, passwd: String?, to fn: (OpaquePointer, UnsafePointer<UInt8>, size_t) -> Int32) throws
    {
        var s = 0
        
        let pwd: UnsafeMutablePointer<Int8>? = passwd?.withCString {
            UnsafeMutablePointer(mutating: $0)
        }
        
        guard let addr = tls_load_file(file, &s, pwd) else {
            throw TLSError.unableToLoadFile(file)
        }
        
        if fn(self.rawValue, addr.cast(to: UInt8.self), s) < 0 {
            throw TLSError.unableToLoadFile(file)
        }
        
    }
    
    @inline(__always)
    private func load1(file: UnsafePointer<Int8>, passwd: String?, to fn: (OpaquePointer, UnsafePointer<UInt8>, size_t) -> Int32) throws
    {
        var s = 0
        
        let pwd: UnsafeMutablePointer<Int8>? = passwd?.withCString {
            UnsafeMutablePointer(mutating: $0)
        }
        print(String(cString: file))
        guard let addr = tls_load_file(file, &s, pwd) else {
            throw TLSError.unableToLoadFile(String(cString: file))
        }
        
        if fn(self.rawValue, addr, s) < 0 {
            throw TLSError.unableToLoadFile(String(cString: file))
        }
    }
    
    private func manual_load_file(_ file: String, _ len: inout Int, _ passwd: String) throws -> UnsafeMutableRawPointer? {
        let fd = open(file, O_RDONLY)
        print(fd)
        var size = 0
        
        if passwd.isEmpty {
            
            size = try FileStatus(fd: fd).size
            let buf = calloc(size + 1, 1)
            len = size
            read(fd, buf, size)
            close(fd)
            return buf
        }
        
        return passwd.withCString {
            let fp = fdopen(fd, "r")
            
            let key = PEM_read_PrivateKey(fp, nil, {
                if $3 == nil {
                    memset($0, 0, Int($1))
                    return 0;
                }
                let len = strlcpy($0, $3!.cast(to: Int8.self), Int($1))
                if len >= UInt($1) {
                    return 0;
                }
                return Int32(len)
            }, UnsafeMutableRawPointer.init(UnsafeMutablePointer<Int8>(mutating: $0)))
            
            let bio = BIO_new(BIO_s_mem())
            PEM_write_bio_PrivateKey(bio, key, nil, nil, 0, nil, nil)
            
            var data: UnsafeMutableRawPointer?
            BIO_ctrl(bio, BIO_CTRL_INFO, 0, data)
            
            let buf = calloc(size + 1, 1)
            memcpy(buf, data!, size)
            BIO_free_all(bio)
            EVP_PKEY_free(key)
            
            len = size
            return buf
        }
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
