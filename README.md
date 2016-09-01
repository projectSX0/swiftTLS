# swiftTLS

##install
swiftTLS is a wrapper of libtls. libtls are imported through system module [libressl-sys](https://github.com/michael-yuji/libressl-sys)
Therefore, please follow the [instruction](https://github.com/michael-yuji/libressl-sys/blob/master/README.md) to initialize libressl-sys first.

##build
```bash
swift build -Xlinker /path/to/libressl/lib -Xcc -I/path/to/libressl/include
```
