import Foundation
import libressl

public enum SSLError : Error {
    case unable2createContext
    case unable2loadCertificate
    case unable2loadPrivateKey
    
    case filedescriptorNotReadable
    case filedescriptorNotWriteable
    
    case tlserror(String)
    case invalidSize
}
