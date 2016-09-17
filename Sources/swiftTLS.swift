import Foundation
import libressl

public enum TLSError : Error {
//    case unable2createContext
//    case unable2loadCertificate
//    case unable2loadPrivateKey

    case unableToLoadFile(String)
    
    case wantPollin
    case wantPollout
    
    case tlserror(String)
    case invalidSize
}
