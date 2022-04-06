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

1. PRF  
2. PRG (done)
2. oblivious transfer (done)
3. garbled circuit
4. secret sharing
5. zk-SNARK
6. add class for Zn and ECPoint/BigInt vector
7. add unified interface for serialization and deserailization
8. wrap _m128i as class?
9. test AES-based hash
10. add multi-point OPRF
11. silient OT
12. change the interfaces of hash: string => char[]?
13. speed serialization of ECPoint
14. overload << >> for serialization


## Specifications

- OS: MAC OS x64, Linux x64
- Language: C++
- Requires: OpenSSL

## Install OpenSSL 3.0 (On MAC OS after Mojave)
```
  $ git clone https://github.com/openssl/openssl.git
  $ ./config 
  $ sudo make install
```

## Install OpenMP (On MAC OS)
```
  $ brew install libomp
```

## Code Structure

- README.md

- CmakeLists.txt: cmake file

- /build

- /include
  * std.inc: standard header files
  * openssl.inc: openssl header files
  * kunlun.hpp: include all necessary files to write a cryptographic program

- /utility: dependent files
  * bit_operation.hpp
  * routines.hpp: related routine algorithms 
  * print.hpp: print info for debug
  * murmurhash3.hpp: add fast non-cryptographic hash
  * polymul.hpp: naive poly mul
  * serialization.hpp: overload serialization for uint and string type data

- /crypto: C++ wrapper for OpenSSL
  * constant.h: define global constants
  * context.hpp: initialize openssl environment
  * ec_group.hpp: initialize ec group environment
  * bigint.hpp: class for BIGNUM
  * ec_point.hpp: class for EC_POINT
  * hash.hpp: all kinds of cryptographic hash function
  * aes.hpp: implement AES using SSE
  * prg.hpp: implement PRG associated algorithms
  * prp.hpp: implement PRP using AES
  * block.hpp: __m128i related algorithms (necessary for exploiting SSE)

- /pke: public key encryption schemes
  * twisted_elgamal.hpp
  * elgamal.hpp
  * calculate_dlog.hpp

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

  - /rpmt
    * cwprf_mqrpmt.hpp: mq-RPMT from commutative weak PRF

  - /pso
    * pso.hpp: support private set intersection, cardinality, sum, union

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


## Compile and Run
```
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ ./test_xxx 
```

---

## Evolution and Updates Log

   * 20210827: post the initial version, mainly consists of wrapper class for BIGNUM* and EC_Point*
   * 20210925: shift twisted elgamal, sigma protocols, bulletproofs, and adcp to Kunlun
   * 20211011: feed my first grammer sugar "namespace" to Kunlun, add OT primitive
   * 20220319: add private set operation and re-org many places 
   * 20220329: speeding Shanks DLOG algorithm and add ElGamal PKE and Schnorr SIG

---

## License

This library is licensed under the [MIT License](LICENSE).

---

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

