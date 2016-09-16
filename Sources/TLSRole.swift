//
//  TLSRole.swift
//  swiftTLS
//
//  Created by yuuji on 8/27/16.
//
//

import Foundation
import FoundationPlus
#if SecureTransport
import SecurityInterface
#else
import libressl
#endif
import CKit

internal protocol TLSRole: OpaqueBridged {
    var config: TLSConfig! { get set }
}

extension TLSRole {
    
    @inline(__always)
    internal func err(_ fn: @autoclosure ()->Int32) throws {
        if fn() < 0 {
            SSLSet
            throw TLSError.tlserror(TLSManager.error(of: self))
        }
    }
    
    #if SecureTransport
    public func read(connection: SSLConnectionRef, bytes: UnsafeMutableRawPointer, len: UnsafeMutablePointer<Int>) -> OSStatus {
        let sockfd = connection.assumingMemoryBound(to: Int32.self).pointee
        return OSStatus(Darwin.read(sockfd, bytes, len.pointee))
    }
    
    public func write(connection: SSLConnectionRef, bytes: UnsafeMutableRawPointer, len: UnsafeMutablePointer<Int>) -> OSStatus {
        let sockfd = connection.assumingMemoryBound(to: Int32.self).pointee
        return OSStatus(Darwin.write(sockfd, bytes, len.pointee))
    }
    
    public func handshake() throws {
        if SSLHandshake(self.context) < 0 {
        
        }
    }
    
    
    /// Close a connection after use. Only the TLS layerll be shut down and the caller is responsible for closing the file descriptors, unless the connection was established using the `connect` or `connect(with:)` method of a `TLSClient`
    public func close() {
        SSLClose(self.context)
    }
    #else
    /// Allocate a buffer with size `size` and read data from the socket to the buffer.
    ///
    /// - parameter size: Number of bytes to read. This will decide the size of memory buffer
    ///
    /// - returns: Bytes read from socket
    public func read(size: Int) throws -> Data {
        
        var buffer = [UInt8](repeating: 0, count: size)
        let count = tls_read(rawValue, &buffer, size)
        
        guard size > 0 else { throw TLSError.invalidSize }
        
        switch Int32(count) {
        case TLS_WANT_POLLIN: throw TLSError.filedescriptorNotReadable
        case TLS_WANT_POLLOUT: throw TLSError.filedescriptorNotWriteable
        default:
            if count < 0 {
                throw TLSError.tlserror(TLSManager.error(of: self))
            }
        }
        return Data(bytes: buffer, count: count)
    }
    
    /// Recursively read data from the socket until no more data availabe. A block with size `blocksize` will be allocate at each cycle
    ///
    /// - parameter blocksize: Number of bytes to read. This will decide the size of memory buffer
    ///
    /// - returns: Bytes read from socket
    public func read(blocksize: Int) throws -> Data {
        
        var blocks = [[UInt8]]()
        var count = -1
        var size = 0
        
        guard blocksize > 0 else { throw TLSError.invalidSize }
        
        repeat {
            var buffer = [UInt8](repeating: 0, count: blocksize)
            count = tls_read(rawValue, &buffer, blocksize)
            switch Int32(count) {
            case TLS_WANT_POLLIN: throw TLSError.filedescriptorNotReadable
            case TLS_WANT_POLLOUT: throw TLSError.filedescriptorNotWriteable
            default:
                if count < 0 {
                    throw TLSError.tlserror(TLSManager.error(of: self))
                }
            }
            size += count
            blocks.append(buffer)
        } while ( count == blocksize )
        
        return Data(bytes: blocks.flatMap{$0}, count: size)
    }
    
    /// Writes data to the socket
    ///
    /// - parameter data: Data to write
    ///
    /// - returns: number of bytes written
    public func write(data: Data) throws -> Int {
        
        let ret = tls_write(rawValue, data.bytes, data.count)
        switch Int32(ret) {
        case TLS_WANT_POLLIN: throw TLSError.filedescriptorNotReadable
        case TLS_WANT_POLLOUT: throw TLSError.filedescriptorNotWriteable
        default:
            if ret < 0 {
                throw TLSError.tlserror(TLSManager.error(of: self))
            }
            return ret
        }
    }
    
    /// Performs the TLS handshake. It is only necessay to call this function if you need to guarantee that the handshake has completed, as both `read` and `write` will perform the TLS handshake if necessary.
    public func handshake() throws {
        if tls_handshake(rawValue) < 0 {
            throw TLSError.tlserror(TLSManager.error(of: self))
        }
    }
    
    
    /// Close a connection after use. Only the TLS layerll be shut down and the caller is responsible for closing the file descriptors, unless the connection was established using the `connect` or `connect(with:)` method of a `TLSClient`
    public func close() {
        tls_close(rawValue)
    }
    #endif
}
