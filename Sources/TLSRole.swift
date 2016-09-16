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
        
        guard size > 0 else {
            throw TLSError.invalidSize
        }
        
        var buffer = [UInt8]()
        var len = 0
        
        recvloop: while(true) {
            var sb = [UInt8](repeating: 0, count: size)
            let count = tls_read(rawValue, &sb, size)
            
            switch Int32(count) {
            case TLS_WANT_POLLIN:
                break recvloop
            case TLS_WANT_POLLOUT:
                break recvloop
            case -1: print(TLSError.tlserror(TLSManager.error(of: self)))
            throw TLSError.tlserror(TLSManager.error(of: self))
            default:
                print(count)
                if count < 0 {
                    throw TLSError.tlserror(TLSManager.error(of: self))
                } else {
                    len += count
                    buffer.append(contentsOf: sb)
                    if count < size {
                        break recvloop
                    }
                }
            }
            
        }
        return Data(bytes: buffer, count: len)
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
    /* supert temp code */
    public func write(data: Data) throws -> Int {
        var len = 0
        var ret = 0
        
        DispatchQueue.global().async {
            repeat {
                ret = tls_write(self.rawValue, data.bytes.advanced(by: len), data.count - len)
                len += ret
                
                switch Int32(ret) {
                case TLS_WANT_POLLIN:
                    TLSError.filedescriptorNotReadable
                case TLS_WANT_POLLOUT:
                    TLSError.filedescriptorNotWriteable
                default:
                    if ret < 0 {
                        TLSError.tlserror(TLSManager.error(of: self))
                    }
                }
                
            } while data.length != len
        }
        return ret
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
