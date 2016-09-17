//
//  TLSRole.swift
//  swiftTLS
//
//  Created by yuuji on 8/27/16.
//
//

import Foundation
import FoundationPlus
import Dispatch

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
            throw TLSError.tlserror(TLSManager.error(of: self))
        }
    }
    
    /* reserved for furture use */
    #if SecureTransport
    public func read(connection: SSLConnectionRef, bytes: UnsafeMutableRawPointer, len: UnsafeMutablePointer<Int>) -> OSStatus {
        let sockfd = connection.assumingMemoryBound(to: Int32.self).pointee
        return OSStatus(Darwin.read(sockfd, bytes, len.pointee))
    }
    
    public func write(connection: SSLConnectionRef, bytes: UnsafeMutableRawPointer, len: UnsafeMutablePointer<Int>) -> OSStatus {
        let sockfd = connection.assumingMemoryBound(to: Int32.self).pointee
        return OSStatus(Darwin.write(sockfd, bytes, len.pointee))
    }
    #endif
    
    /// Allocate a buffer with size `size` and read data from the socket to the buffer.
    ///
    /// - parameter size: Number of bytes to read. This will decide the size of memory buffer
    ///
    /// - throws: wantPollin if further read is required. wantPollout if further write is required. Detail in [OpenBSD man page](http://man.openbsd.org/OpenBSD-current/man3/tls_init.3)
    ///
    /// - returns: Bytes read from socket
    public func read(size: Int) throws -> Data {
        let size = 16384 /* internal buffer size of openssl / libressl */
        var sb = [UInt8](repeating: 0, count: size)
        let count = tls_read(self.rawValue, &sb, size)
        
        switch Int32(count) {
        case -1:
            throw TLSError.tlserror(TLSManager.error(of: self))
        case TLS_WANT_POLLIN:
            throw TLSError.wantPollin
        case TLS_WANT_POLLOUT:
            throw TLSError.wantPollout
        default:
            return Data(bytes: sb, count: count)
        }
    }
    
    /// Writes data to the socket
    ///
    /// - parameter data: Data to write
    ///
    /// - returns: number of bytes written
    /* super temp code */
    public func write(data: Data) throws -> Int {
        var ret = 0
        
        let magicNumber = 16384
        
        let remains = data.length % magicNumber
        let nchunk = (data.length / magicNumber) + (remains == 0 ? 0 : 1)
        
        
        for nth_chunk in 0..<nchunk {
            /* The logic can be confusing here:
             * If nth_chunk == nchunk - 1 //last chunk
             *       if remains is 0??
             *           if the remainder is zero, means, the last call does not zeros bytes out
             *               so there will be `magicNumber` bytes of data
             *           otherwise, write the size of remainder
             * else -> It is a whole chunk
             *       size = magicNumber
             */
            ret = tls_write(self.rawValue, data.bytes.advanced(by: magicNumber * nth_chunk), nth_chunk == (nchunk - 1) ? remains == 0 ? magicNumber : remains : magicNumber)
            switch Int32(ret) {
            case TLS_WANT_POLLIN:
                throw TLSError.wantPollin
            case TLS_WANT_POLLOUT:
                throw TLSError.wantPollout
            default:
                if ret < 0 {
                    throw TLSError.tlserror(TLSManager.error(of: self))
                }
            }
        }
        
        return data.length
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
}
