# Kunlun: A Modern Crypto Library

## Overview

I give a C++ wrapper for OpenSSL, making it handy to use, without worrying about the cumbersome memory management and memorizing the complex interfaces. Based on this wrapper, I am going to build an efficient and modular crypto library. 

## Design Philosophy

Provide a set of neat interfaces for big integer and ec group operations, with the hope that the code is as succinct as paper description. Kunlun supports multithreading via OpenMP. So far, the library is not stable. It will keep evolving. 

## Issues

* OpenSSL does not support pre-computation for customized generator.
* bn_ctx is not thread-safe, so in many places it is hard to apply the SIMD parallel optimization. 
* A dirty trick is to make openssl-based programs parallizable is to set bn_ctx = nullptr. This trick works for some cases but not all, and only beats the single-thread programs when THREAD_NUM is much larger than 1.  

If the above two issues get solved, the performance of Kunlun will be better.

## To do list (impossible missions for me)

* PRF  
* garbled circuit
* secret sharing
* zk-SNARK
* add class for Zn and ECPoint/BigInt vector
* wrap _m128i as class?
* silient OT
* overload << >> for serialization


## Specifications

- OS: MAC OS x64, Linux x64
- Language: C++
- Requires: OpenSSL, OpenMP

## Install Depedent Libaraies
### On MACOS
* download the latest OpenSSL from the website, to support curve25519, 
modify crypto/ec/curve25519.c line 211: remove "static", then compile it:
```
  $ ./Configure darwin64-x86_64-cc shared enable-ec_nistp_64_gcc_128 no-ssl2 no-ssl3 no-comp --openssldir=/usr/local/ssl/macos-x86_64
  $ make depend
  $ sudo make install
```

test if the function x25519_scalar_mulx is available
```
  $ cd /usr/local/lib
  $ nm libcrypto.a | grep x25519_scalar_mulx
```

* install OpenMP
```
  $ brew install libomp 
```

<!-- * install abseil-cpp
```
  $ git clone git@github.com:abseil/abseil-cpp.git 
  $ mkdir build && cd build
  $ cmake -DABSL_BUILD_TESTING=ON -DABSL_USE_GOOGLETEST_HEAD=ON -DCMAKE_CXX_STANDARD=14 ..
  $ make install
``` -->


### On Linux
* install OpenSSL 3.0

do the same modification as in MACOS, then compile it according to
```
  $ ./Configure no-shared enable-ec_nistp_64_gcc_128 no-ssl2 no-ssl3 no-comp --prefix=/usr/local/openssl
  $ make depend
  $ sudo make install
```

if reporting cannot find "opensslv.h" error, try to install libssl-dev
```
  $ sudo apt-get install libssl-dev 
```

* install OpenMP
```
  $ sudo apt-get install libomp-dev 
```

## Code Structure

- README.md

- CmakeLists.txt: cmake file

- /build

- /include
  * std.inc: standard header files
  * openssl.inc: openssl header files
  * global.hpp: define global variables for kunlun lib as well as error information

- /utility: dependent files
  * bit_operation.hpp
  * routines.hpp: related routine algorithms 
  * print.hpp: print info for debug
  * murmurhash3.hpp: add fast non-cryptographic hash
  * polymul.hpp: naive poly mul
  * serialization.hpp: overload serialization for uint and string type data

- /crypto: C++ wrapper for OpenSSL
  * setup.hpp: initialize crypto environments, including big number, elliptic curves, and aes
  * ec_group.hpp: initialize ec group environment, define compressed-point on-off, precomputation on-off 
  * ec_point.hpp: class for EC_POINT of ordinary EC curves 
  * ec_25519.hpp: class for x25519 method of specific Curve25519 
  * bigint.hpp: class for BIGNUM, also include initialization of big num
  * hash.hpp: all kinds of cryptographic hash functions
  * aes.hpp: implement AES using SSE, as well as initialization of aes
  * prg.hpp: implement PRG associated algorithms
  * prp.hpp: implement PRP using AES
  * block.hpp: __m128i related algorithms (necessary for exploiting SSE)

- /pke: public key encryption schemes
  * twisted_exponential_elgamal.hpp
  * exponential_elgamal.hpp
  * elgamal.hpp: standard ElGamal PKE whose message space is G 
  * calculate_dlog.hpp: implement optimized general Shank's algorithm

- /signature
  * schnorr.hpp
  * accountable_ring_signature.hpp: implement accountable ring signature

- /commitment
  * pedersen.hpp: multi-element Pedersen commitment

- /gadgets
  * range_proof.hpp: two useful gadgets for proving encrypted values lie in the right range

- /cryptocurrency
  * adcp.hpp: the adcp system 

- /netio
  * stream_channel.hpp: basic network socket functionality

- mpc
  - /ot
    * naor_pinkas_ot.hpp: one base OT
    * iknp_ote.hpp: IKNP OT extension

  - /oprf
    * ote_oprf: OTE-based OPRF
    * ddh_oprf: DDH-based (permuted)-OPRF
    * vole_oprf: VOLE-based OPRF

  - /rpmt
    * cwprf_mqrpmt.hpp: mq-RPMT from commutative weak PRF

  - /pso
    * mqrpmt_psi.hpp: set intersection
    * mqrpmt_psi_card.hpp: intersection cardinality
    * mqrpmt_psi_card_sum.hpp: intersection sum and cardinality 
    * mqrpmt_psu.hpp: union
    * mqrpmt_private_id.hpp: private-id protocol based on OTE-based OPRF and cwPRF-based mqRPMT

  - /okvs
    * baxos.hpp
    * ovks_utility.hpp
    * paxos.hpp

  - /vole
    * basevole.hpp
    * exconvcode.hpp
    * vole.hpp
  

- zkp
  - /nizk: associated sigma protocol for twisted elgamal; obtained via Fiat-Shamir transform  
    * nizk_plaintext_equality.hpp: NIZKPoK for twisted ElGamal plaintext equality in 3-recipient mode
    * nizk_plaintext_knowledge.hpp: NIZKPoK for twisted ElGamal plaintext and randomness knowledge
    * nizk_dlog_equality.hpp: NIZKPoK for discrete logarithm equality
    * nizk_dlog_knowledge.hpp: Schnorr protocol for dlog
    * nizk_enc_relation.hpp: prove one-out-of-n ciphertexts is encryption of 0

  - /bulletproofs
    * bullet_proof.hpp: the aggregating logarithmic size bulletproofs
    * innerproduct_proof.hpp: the inner product argument (used by Bulletproof to shrink the proof size) 

- /filter
  * bloom_filter.hpp
  * cuckoo_filter.hpp

- /docs: the manual of all codes

---

## Compile and Run
```
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ ./test_xxx 
```

---

## Multi-threads Support
- Kunlun supports multithread by leveraging openmp. The underlying OpenSSL is not thread-safe, cause several threads may access a critial data structure "bn_ctx" concurrently. Kunlun is made thread-safe by introducing an array of bn_ctx. Thus, each thread has its own bn_ctx.     

- The global setting for multi-thread support lies at "include/global.hpp" line 19

- For multi-thread (n)
```
inline const size_t NUMBER_OF_THREADS = n; 
the default value of n is NUMBER_OF_PHYSICAL_CORES 
```

- For single-thread
```
inline const size_t NUMBER_OF_THREADS = 1; 
```

## Elliptic curve setting
- Kunlun supports all EC curves provided by OpenSSL. The global setting of EC curves lies at "crypto/ec_group.hpp" line 16-18. 

```
inline int curve_id = NID_X9_62_prime256v1; // choose other curves by specifying curve-ID  
#define ECPOINT_COMPRESSED                  // comment this line to enable uncompressed representation
#define ENABLE_X25519_ACCELERATION      // (un)comment this line to enable x25519 acceleration method
```

Note: x22519 is an efficnet DDH-based non-interactive key exchange (NIKE) protocol based on curve25519. The essense of x25519 is exactly cwPRF. Its remarkable efficency is attained by performing "somehow EC exponentiation" with only X-coordinates (perhaps x25519 name after it). However, in x25519 the EC exponetiation is not standard, and EC addition is not well-defined. We stress that curve25519 certainly support standard EC exponentiation and addition, but x25519 method does not. Kunlun provides the option of using x25519 method to improve performance of applications when it is applicable (involving only cwPRF). But, since x25519 method is not full-fledged, ordinary EC curves are always necessary for base Naor-Pinkas OT. Therefore, users must specify one ordinary EC curve when implementing ECC.    

## Evolution and Updates Log

   * 20210827: post the initial version, mainly consists of wrapper class for BIGNUM* and EC_Point*
   * 20210925: shift twisted elgamal, sigma protocols, bulletproofs, and adcp to Kunlun
   * 20211011: feed my first grammar sugar "namespace" to Kunlun, add OT primitive
   * 20220319: add private set operation and re-org many places 
   * 20220329: speeding Shanks DLOG algorithm and add ElGamal PKE and Schnorr SIG
   * 20220605: greatly improve the multi-thread support (simplify the code and unify the interface)
   * 20230719: refine multi-thread support (fix bugs and improve performance)

---

## License

This library is licensed under the [MIT License](LICENSE).

---

## Acknowledgement

We deeply thank [Weiran Liu](https://www.zhihu.com/people/liu-wei-ran-8-34) for many helpful discussions on the development of this library. Here we strongly recommend the efficient and easy-to-use [MPC library for Java](https://github.com/alibaba-edu/mpc4j) developed by his team. 
I thank my deer senior apprentice [Prof. Zhi Guan](http://gmssl.org/) for professional help. 

## Tips

* thread vector is more efficient than thread array: I don't know the reason why
* add mutex to lock bn_ctx will severely harm the performance of multi thread 
* void* type pointer allow you to determine the exact type later and provide a unified interface

---

## How to test the speed of socket communication?

1. install iperf3 via the following command
```
brew install iperf3
```

2. open it in two terminals (perhaps on two computers)
```
iperf3 -s
iperf3 -c [IP Address of first Mac]
```

See more information via https://www.macobserver.com/tmo/answers/how-to-test-speed-home-network-iperf

