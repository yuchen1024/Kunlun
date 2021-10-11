/****************************************************************************
this hpp implements twisted ElGamal PKE scheme
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef PKE_TWISTED_ELGAMAL_HPP_
#define PKE_TWISTED_ELGAMAL_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../common/routines.hpp"
#include "calculate_dlog.hpp"

// babystep hashkey table: crucial for implement Shanks algorithm
const std::string keytable_filename  = "babystep_hashkey.table"; 

namespace TwistedElGamal{

// define the structure of PP
struct PP
{
    size_t MSG_LEN; // the length of message space, also the length of the DLOG interval  
    BigInt MSG_SIZE; // the size of message space
    size_t TRADEOFF_NUM; // default value = RANGE_LEN/2; tunning it in [0, RANGE_LEN/2], ++ leads bigger table and less time 
    size_t DEC_THREAD_NUM; // optimized number of threads for faster decryption: CPU dependent

    ECPoint g; 
    ECPoint h; // two random generators 
};

// define the structure of keypair
struct KP
{
    ECPoint pk;  // define pk
    BigInt sk;    // define sk
};

// define the structure of ciphertext
struct CT
{
    ECPoint X; // X = pk^r 
    ECPoint Y; // Y = g^m h^r 
};

// define the structure of multi-recipients one-message ciphertext (MR denotes multiple recipients)
struct MRCT
{
    std::vector<ECPoint> X; // X_i = pk_i^r
    ECPoint Y; // Y = g^r h^m 
};


void PrintPP(const PP &pp)
{
    std::cout << "the length of message space = " << pp.MSG_LEN << std::endl; 
    std::cout << "the trade-off parameter for fast decryption = " << pp.TRADEOFF_NUM << std::endl;
    std::cout << "the optimal decryption thread num = " << pp.DEC_THREAD_NUM << std::endl;
    pp.g.Print("pp.g"); 
    pp.h.Print("pp.h"); 
} 

void PrintKP(const KP &keypair)
{
    keypair.pk.Print("pk"); 
    keypair.sk.Print("sk"); 
} 

void PrintCT(const CT &ct)
{
    ct.X.Print("CT.X");
    ct.Y.Print("CT.Y");
} 


void SerializeCT(CT &ct, std::ofstream &fout)
{
    ct.X.Serialize(fout); 
    ct.Y.Serialize(fout); 
} 

void DeserializeCT(CT &ct, std::ifstream &fin)
{
    ct.X.Deserialize(fin); 
    ct.Y.Deserialize(fin); 
} 


/* Setup algorithm */ 
void Setup(PP &pp, size_t MSG_LEN, size_t TRADEOFF_NUM, size_t DEC_THREAD_NUM)
{ 
    pp.MSG_LEN = MSG_LEN; 
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 
    pp.DEC_THREAD_NUM = DEC_THREAD_NUM;
    /* set the message space to 2^{MSG_LEN} */
    pp.MSG_SIZE = BigInt(size_t(pow(2, pp.MSG_LEN))); 

    #ifdef DEBUG
        std::cout << "message space = [0, ";   
        std::cout << BN_bn2hex(pp.MSG_SIZE.bn_ptr) << ')' << std::endl; 
    #endif
  
    pp.g = ECPoint(generator); 

    /* generate pp.h via deterministic and transparent manner */
    pp.h = Hash::StringToECPoint(pp.g.ToByteString());   

    #ifdef DEBUG
        std::cout << "generate the public parameters for twisted ElGamal >>>" << std::endl; 
        PrintPP(pp); 
    #endif
}


/* initialize the hashmap to accelerate decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize Twisted ElGamal PKE >>>" << std::endl; 
    /* generate babystep table */
    if(!FileExist(keytable_filename))
    {
        // generate and serialize the babystep table
        if(pp.DEC_THREAD_NUM > 1){
            ParallelBuildSerializeKeyTable(pp.h, pp.MSG_LEN, pp.TRADEOFF_NUM, pp.DEC_THREAD_NUM, keytable_filename);
        }
        if(pp.DEC_THREAD_NUM == 1){
            BuildSerializeKeyTable(pp.h, pp.MSG_LEN, pp.TRADEOFF_NUM, keytable_filename);
        }
    }
    // load the table from file 
    DeserializeKeyTableBuildHashMap(keytable_filename, pp.MSG_LEN, pp.TRADEOFF_NUM); 
}



/* KeyGen algorithm */ 
void KeyGen(const PP &pp, KP &keypair)
{ 
    keypair.sk = GenRandomBigIntLessThan(order); // sk \sample Z_p
    keypair.pk = pp.g * keypair.sk; // pk = g^sk  

    #ifdef DEBUG
        std::cout << "key generation finished >>>" << std::endl;  
        PrintKP(keypair); 
    #endif
}

/* Encryption algorithm: compute CT = Enc(pk, m; r) */ 
void Enc(const PP &pp, const ECPoint &pk, const BigInt &m, CT &ct)
{ 
    // generate the random coins 
    BigInt r = GenRandomBigIntLessThan(order); 

    // begin encryption
    ct.X = pk * r; // X = pk^r
    
    // vectormul using wNAF method, which is fast than naive ct.Y = pp.g * r + pp.h * m;  
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_a{r, m};
    ct.Y = ECPointVectorMul(vec_A, vec_a);     // Y = g^r h^m

    #ifdef DEBUG
        std::cout << "twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif
}

/* Encryption algorithm: compute CT = Enc(pk, m; r): with explicit randomness */ 
void Enc(const PP &pp, const ECPoint &pk, const BigInt &m, const BigInt &r, CT &ct)
{ 
    // begin encryption
    ct.X = pk * r; // X = pk^r
    //CT.Y = pp.g * r + pp.h * m; // Y = g^r h^m
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_a{r, m};
    ct.Y = ECPointVectorMul(vec_A, vec_a); 

    #ifdef DEBUG
        std::cout << "twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif
}

/* Decryption algorithm: compute m = Dec(sk, CT) */ 
void Dec(const PP &pp, const BigInt& sk, const CT &ct, BigInt &m)
{ 
    //begin decryption  
    ECPoint M = ct.Y - ct.X * sk.ModInverse(order); // M = Y - X^{sk^{-1}} = h^m 

    bool SUCCESS;
    //Brute_Search(pp.h, M, m);
    if(pp.DEC_THREAD_NUM == 1){
        // use Shanks's algorithm to decrypt
        SUCCESS = ShanksDLOG(pp.h, M, pp.MSG_LEN, pp.TRADEOFF_NUM, m); 
    }
    else{
        SUCCESS = ParallelShanksDLOG(pp.h, M, pp.MSG_LEN, pp.TRADEOFF_NUM, pp.DEC_THREAD_NUM, m); 
    }
    if(SUCCESS == false)
    {
        std::cout << "decyption fails in the specified range" << std::endl; 
        exit(EXIT_FAILURE); 
    }  
}

/* Encaps algorithm: compute (CT, k) = Encaps(pk, r): where CT = pk^r, k = g^r */ 
void Encaps(const PP &pp, const ECPoint &pk, ECPoint &ct, ECPoint &key)
{ 
    // begin encryption
    BigInt r = GenRandomBigIntLessThan(order); 
    ct = pk * r; // ct = pk^r
    key = pp.g * r; // KEY = g^r

    #ifdef DEBUG
        std::cout << "twisted ElGamal encapsulation finishes >>>"<< std::endl;
        ct.Print("ciphertext");
        key.Print("session key");  
    #endif
}

/* Decaps algorithm: compute KEY = Decaps(sk, ct) */ 
void Decaps(const PP &pp, const BigInt &sk, const ECPoint &ct, ECPoint &key)
{ 
    //begin decryption  
    key = ct * (sk.ModInverse(order)); // KEY = CT^{sk^{-1}} = g^r 

    #ifdef DEBUG
        std::cout << "twisted ElGamal decapsulation finishes >>>"<< std::endl;
        key.Print("session key");  
    #endif
}

/* re-encrypt ciphertext CT with given randomness r */ 
void ReEnc(const PP &pp, const ECPoint &pk, const BigInt &sk, const CT &ct, const BigInt &r, CT &ct_new)
{ 
    // begin partial decryption  
    ECPoint M = ct.Y - ct.X * (sk.ModInverse(order)); // M = Y - X^{sk^{-1}} = h^m

    // begin re-encryption with the given randomness 
    ct_new.X = pk * r; // CT_new.X = pk^r 
    ct_new.Y = pp.g * r + M; // CT_new.Y = g^r 

    #ifdef DEBUG
        std::cout << "refresh ciphertext succeeds >>>"<< std::endl;
        PrintCT(ct_new); 
    #endif
}


/* homomorphic add */
void HomoAdd(CT &ct_result, const CT &ct1, const CT &ct2)
{ 
    ct_result.X = ct1.X + ct2.X;  
    ct_result.Y = ct1.Y + ct2.Y;  
}

/* homomorphic sub */
void HomoSub(CT &ct_result, const CT &ct1, const CT &ct2)
{ 
    ct_result.X = ct1.X - ct2.X;  
    ct_result.Y = ct1.Y - ct2.Y;  
}

/* scalar operation */
void ScalarMul(CT &ct_result, const CT &ct, const BigInt &k)
{ 
    ct_result.X = ct.X * k;  
    ct_result.Y = ct.Y * k;  
}

/* Decryption algorithm: compute m = Dec(sk, CT) */
void ParallelDec(const PP &pp, BigInt &sk, CT &ct, BigInt &m)
{ 
    /* begin to decrypt */  
    ECPoint M = ct.Y - ct.X * sk.ModInverse(BigInt(order)); // M = Y - X^{sk^{-1}} = h^m 

    // use Shanks's algorithm to decrypt
    bool SUCCESS = ParallelShanksDLOG(pp.h, M, pp.MSG_LEN, pp.TRADEOFF_NUM, pp.DEC_THREAD_NUM, m); 
  
    if(SUCCESS == false)
    {
        std::cout << "parallel decyption fails: cannot find the message in the specified range" << std::endl; 
        exit(EXIT_FAILURE); 
    }  
}


/* 
* Encryption algorithm (2-recipients 1-message) with given random coins
* output X1 = pk1^r, X2 = pk2^r, Y = g^r h^m
* Here we make the randomness explict for the ease of generating the ZKP 
*/

void PrintCT(const MRCT &ct)
{
    ct.X[0].Print("CT.X1");
    ct.X[1].Print("CT.X2");
    ct.X[2].Print("CT.X3");
    ct.Y.Print("CT.Y");
} 

void Enc(const PP &pp, const std::vector<ECPoint> &vec_pk, const BigInt &m, const BigInt &r, MRCT &ct)
{  
    size_t n = vec_pk.size();
    for(auto i = 0; i < n; i++){
        ct.X.push_back(vec_pk[i] * r); 
    }
 
    ct.Y = pp.g * r + pp.h * m; // Y = g^r h^m
   
    #ifdef DEBUG
        std::cout << n <<"-recipient 1-message twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif
}




void SerializeCT(MRCT &ct, std::ofstream& fout)
{
    for(auto i = 0; i < ct.X.size(); i++){
        ct.X[i].Serialize(fout); 
    }
    ct.Y.Serialize(fout); 
} 

void DeserializeCT(MRCT &ct, std::ifstream& fin)
{
    for(auto i = 0; i < ct.X.size(); i++){
        ct.X[i].Deserialize(fin); 
    }
    ct.Y.Deserialize(fin); 
}

}
# endif


//deprecated code

/* parallel implementation */

/*
* https://www.openssl.org/docs/manmaster/man3/BN_CTX_new.html
* A given BN_CTX must only be used by a single thread of execution. 
* No locking is performed, and the internal pool allocator will not properly handle multiple threads of execution. 
* Thus, in multithread programming, a lazy and safe approach is setting bn_ctx = NULL
*/

/* parallel homomorphic add */

// void ParallelHomoAdd(CT &ct_result, CT &ct1, CT &ct2)
// { 
//     std::thread add_thread1(ThreadSafe_ECPoint_Add, std::ref(ct_result.X), std::ref(ct1.X), std::ref(ct2.X));
//     std::thread add_thread2(ThreadSafe_ECPoint_Add, std::ref(ct_result.Y), std::ref(ct1.Y), std::ref(ct2.Y));

//     add_thread1.join(); 
//     add_thread2.join(); 
// }


// void ParallelHomoSub(CT &ct_result, CT &ct1, CT &ct2)
// { 
//     std::thread sub_thread1(ThreadSafe_ECPoint_Sub, std::ref(ct_result.X), std::ref(ct1.X), std::ref(ct2.X));
//     std::thread sub_thread2(ThreadSafe_ECPoint_Sub, std::ref(ct_result.Y), std::ref(ct1.Y), std::ref(ct2.Y));

//     sub_thread1.join(); 
//     sub_thread2.join(); 
// }

// /* parallel scalar operation */
// void ParallelScalarMul(CT &ct_result, CT &ct, BigInt &k)
// { 
//     std::thread scalar_thread1(ThreadSafe_ECPoint_Mul, std::ref(ct_result.X), std::ref(ct.X), std::ref(k));
//     std::thread scalar_thread2(ThreadSafe_ECPoint_Mul, std::ref(ct_result.Y), std::ref(ct.Y), std::ref(k));
    
//     // synchronize threads
//     scalar_thread1.join(); 
//     scalar_thread2.join(); 
// }

// parallel re-encryption
// void ParallelReEnc(PP &pp, ECPoint &pk, BigInt &sk, CT &ct, BigInt &r, CT &ct_new)
// { 
//     /* partial decryption: only recover M = h^m */  

//     ECPoint M = ct.Y - ct.X * sk.ModInverse(order);  

//     /* re-encryption with the given randomness */
//     std::thread reenc_thread1(ThreadSafe_ECPoint_Mul, std::ref(ct_new.X), std::ref(pk), std::ref(r));
//     std::thread reenc_thread2(ThreadSafe_ECPoint_Mul, std::ref(ct_new.Y), std::ref(pp.g), std::ref(r));

//     reenc_thread1.join(); 
//     reenc_thread2.join(); 

//     ct_new.Y = ct_new.Y + M;    // Y = g^r h^m
// }


// /* Parallel Encryption algorithm: compute CT = Enc(pk, m; r) */
// void ParallelEnc(PP &pp, ECPoint &pk, BigInt &m, CT &ct)
// { 
//     /* generate fresh randomness */ 
//     BigInt r = GenRandomBigIntLessThan(BigInt(order)); 

//     std::vector<ECPoint> A{pp.g, pp.h}; 
//     std::vector<BigInt> a{r, m};   
//     std::thread enc_thread1(ThreadSafe_ECPoint_Mul, std::ref(ct.X), std::ref(pk), std::ref(r)); 
//     std::thread enc_thread2(ThreadSafe_ECPointVector_Mul, std::ref(ct.Y), std::ref(A), std::ref(a));

//     // synchronize threads
//     enc_thread1.join();                // pauses until first finishes
//     enc_thread2.join();               // pauses until second finishes
// }





