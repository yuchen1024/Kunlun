# Kunlun: A Modern Crypto Library

## Overview

We give a C++ wrapper for OpenSSL, make it handy to use, without worrying about the cumbersome memory management and memorizing the long interfaces. Based on this wrapper, we are going to build an efficient and modular crypto library.   


## Specifications

- OS: MAC OS x64, Linux x64
- Language: C++
- Requires: OpenSSL

## Install OpenSSL (On Linux)
download [openssl-master.zip](https://github.com/openssl/openssl.git), then
```
  $ mkdir openssl
  $ mv openssl-master.zip /openssl
  $ unzip openssl-master.zip
  $ cd openssl-master
  $ ./config shared
  $ ./make
  $ ./make test
  $ ./make install
```


## Code Structure

- README.md

- CmakeLists.txt: cmake file

- /build

- /common: dependent files
  * routines.hpp: related routine algorithms 
  * print.hpp: print info for debug

- /crypto: C++ wrapper for OpenSSL
  * context.hpp: initialize openssl environment
  * ec_group.hpp: initialize ec group environment
  * bigint.hpp: class for BIGNUM
  * ec_point.hpp: class for EC_POINT
  * hash.hpp: related hash function
  * std.inc: standard header files
  * openssl.inc: openssl header files

- /twisted_elgamal_pke: twisted elgamal pke

- /test: test files
  * test_twisted_elgamal.cpp:



## Compile and Run
```
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ ./test_twisted_elgamal 
```

## License

This library is licensed under the [MIT License](LICENSE).

