# Kunlun: A Modern Crypto Library

## Overview

I give a C++ wrapper for OpenSSL, making it handy to use, without worrying about the cumbersome memory management and memorizing the complex interfaces. Based on this wrapper, I am going to build an efficient and modular crypto library. 

## Design Philosophy

Provide a set of neat interfaces for big integer and ec group operations, with the hope that the code is as succinct as paper description. However, the style of interfaces is hard to unify. So far, the library is not stable. It will keep evolving. 

## Issues

* OpenSSL does not support pre-computation for customized generator.
* bn_ctx is not thread-safe, so in many places it is hard to apply the SIMD parallel optimization. 
* A dirty trick is to make openssl-based programs parallizable is to set bn_ctx = nullptr. This trick works for some cases but not all, and only beats the single-thread programs when THREAD_NUM is much larger than 1.  

If the above two issues get solved, the performance of Kunlun will be better.

## To do list (impossible missions for me)

1. PRF, PRG (done)
2. oblivious transfer (done)
3. garbled circuit
4. secret sharing
5. zk-SNARK
6. add class for Zn and ECPoint/BigInt vector


## Specifications

- OS: MAC OS x64, Linux x64
- Language: C++
- Requires: OpenSSL

## Install OpenSSL 3.0 (On MAC OS)
```
  $ git clone https://github.com/openssl/openssl.git
  $ ./config 
  $ make install
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

- /utility: dependent files
  * routines.hpp: related routine algorithms 
  * print.hpp: print info for debug

- /crypto: C++ wrapper for OpenSSL
  * constant.h: define global constants
  * context.hpp: initialize openssl environment
  * ec_group.hpp: initialize ec group environment
  * bigint.hpp: class for BIGNUM
  * ec_point.hpp: class for EC_POINT
  * hash.hpp: related hash function
  * aes.hpp: implement AES using SSE
  * prg.hpp: implement PRG associated algorithms
  * prp.hpp: implement PRP using AES
  * block.hpp: __m128i related algorithms (necessary for exploiting SSE)

- /pke: public key encryption schemes
  * twisted_elgamal.hpp
  * calculate_dlog.hpp

- /nizk: associated sigma protocol for twisted elgamal; obtained via Fiat-Shamir transform  
  * nizk_plaintext_equality.hpp: NIZKPoK for twisted ElGamal plaintext equality in 3-recipient mode
  * nizk_plaintext_knowledge.hpp: NIZKPoK for twisted ElGamal plaintext and randomness knowledge
  * nizk_dlog_equality.hpp: NIZKPoK for discrete logarithm equality

- /bulletproofs
  * bullet_proof.hpp: the aggregating logarithmic size bulletproofs
  * innerproduct_proof.hpp: the inner product argument (used by Bulletproof to shrink the proof size) 

- /gadgets
  * range_proof.hpp: two useful gadgets for proving encrypted values lie in the right range

- /cryptocurrency
  * adct.hpp: the ADCT system 

- /netio
  * stream_channel.hpp: basic network socket functionality for OT

- /ot
  * naor_pinkas_ot.hpp: one base OT
  * chou_orlandi_ot.hpp: another base OT
  * iknp_ote.hpp: IKNP OT extension

- /psi
  * dh-psi.hpp

- /psu
  * dh-psu.hpp

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
   * 20210925: shift twisted elgamal, sigma protocols, bulletproofs, and ADCT to Kunlun
   * 20211011: feed my first grammer sugar "namespace" to Kunlun, add OT primitive 

---

## Demo with Test Cases of ADCT


set the range size = $[0, 2^\ell = 2^{32}-1 = 4294967295]$

### Flow of ADCT_Demo

   1. run <font color=blue>Setup:</font> to build up the system, generating system-wide parameters and store them in "common.para"
   2. run <font color=blue>Create_Account</font> to create accounts for Alice ($m_1$) and Bob ($m_2$); 
      one can reveal the balance by running <font color=blue>Reveal_Balance:</font> 
   3. Alice runs <font color=blue>Create_CTx</font> to transfer $v_1$ coins to Bob ===> Alice_sn.ctx; 
      <font color=blue>Print_CTx:</font> shows the details of CTx
   4. Miners runs <font color=blue>Verify_CTx:</font> check CTx validity
   5. If CTx is valid, run <font color=blue>Update_Account</font> to Update Alice and Bob's account balance and serialize the changes.

### Support to Auditing Polices

   * Selective opne policy: either Alice or Bob can reveal the transfer amount of related CTx in dispute by running <font color=blue>Justify_open_policy</font>. Anyone can check if the transfer amount is correct by running <font color=blue>Audit_open_policy</font>. 
   
   * Anti-money laundering policy: sender can prove the transfer amount sum of a collection of ctx sent from him does not exceed a give limit by running <font color=blue>Justify_limit_policy</font>. Anyone can check if the transfer amount is correct by running <font color=blue>Audit_limit_policy</font>. 

   * Tax policy: user can prove he paid the incoming tax according to the rules by running <font color=blue>Justify_tax_policy</font>. Anyone can check if the transfer amount is correct by running <font color=blue>Audit_tax_policy</font>. 



### Test Cases
---
Create ADCT environment

1. setup the ADCT system


2. generate three accounts: Alice, Bob and Tax
   * $512$ --- Alice's initial balance  
   * $256$ --- Bob's initial balance    
   * $0$   --- Tax's initial balance


3. serialize pp and three accounts

---
Test basic transactions among Alice, Bob and Tax

0. deserialize pp and three accounts

1. Invalid CTx: <font color=red>$v_1 \neq v_2$ $\Rightarrow$ plaintext equality proof will be rejected</font>  
   - $v_1 \neq v_2$ --- in transfer amount


2. Invalid CTx: <font color=red>$v \notin [0, 2^\ell]$ $\Rightarrow$ range proof for right interval will be rejected</font>
   - $v  = 4294967296$ --- transfer amount      


3. Invalid CTx: <font color=red>$(m_1 - v) \notin [0, 2^\ell]$ $\Rightarrow$ range proof for solvent 
   will be rejected</font>
   - $m_1  = 384$ --- Alice's updated balance  
   - $v  = 385$ --- transfer amount 

4. 1st Valid CTx
   - $v    = 128$ --- transfer amount from Alice to Bob
   - $384$ --- Alice's updated balance  
   - $384$ --- Bob's updated balance    
   - $0$   --- Tax's updated balance

5. 2nd Valid CTx
   - $v    = 32$ --- transfer amount from Bob to Alice
   - $384$ --- Alice's updated balance  
   - $352$ --- Bob's updated balance    
   - $32$   --- Tax's updated balance


6. 3st Valid CTx:
   - $v    = 384$ --- transfer amount from Alice to Bob
   - $0$ --- Alice's updated balance  
   - $736$ --- Bob's updated balance    
   - $32$   --- Tax's updated balance

---
Test auditing policies

1. Open policy: for ctx1
   - $v_1  = 128$ --- Alice's claim (correct)  
   - $v_2  = 127$ --- Bob's claim (false)  


2. Tax policy: for ctx1 and ctx2
   - tax rate is 1/4 --- Bob's claim (correct)


3. Limit policy: for ctx1 and ctx3
   - limit is 512 --- Alice's claim (false) 
   - limit is 513 --- Alice's claim (correct)      

---


## License

This library is licensed under the [MIT License](LICENSE).

---

## Tips

* thread vector is more efficient than thread array: I don't know the reason why
* add mutex to lock bn_ctx will severely harm the performance of multi thread 

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

