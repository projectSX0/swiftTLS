import PackageDescription

let package = Package(
    name: "swiftTLS",
    dependencies: [.Package(url: "https://github.com/michael-yuji/libressl-sys.git",
                            versions: Version(0,0,0)..<Version(1,0,0)),
                   .Package(url: "https://github.com/michael-yuji/FoundationPlus.git",
                            versions: Version(0,0,0)..<Version(1,0,0)),
                   .Package(url: "https://github.com/michael-yuji/CKit.git",
                            versions: Version(0,0,0)..<Version(1,0,0))]
)
