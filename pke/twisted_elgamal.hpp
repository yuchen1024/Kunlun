#ifndef TWISTED_ELGAMAL_HPP_
#define TWISTED_ELGAMAL_HPP_

#include "../include/kunlun.hpp"
#include "calculate_dlog.hpp"

namespace TwistedElGamal{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define the structure of PP
struct PP
{
    size_t MSG_LEN; // the length of message space, also the length of the DLOG interval  
    BigInt MSG_SIZE; // the size of message space
    size_t TRADEOFF_NUM; // default value = RANGE_LEN/2; tunning it in [0, RANGE_LEN/2], ++ leads bigger table and less time 
    ECPoint g, h; // two random generators 
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
    std::vector<ECPoint> vec_X; // X_i = pk_i^r
    ECPoint Y; // Y = g^r h^m 
};


// compare two ciphertexts
bool operator==(const CT& ct_left, const CT& ct_right)
{
    return (ct_left.X == ct_right.X) && (ct_left.Y == ct_right.Y);  
}

// define serialization interfaces
void PrintPP(const PP &pp)
{
    std::cout << "the length of message space = " << pp.MSG_LEN << std::endl; 
    std::cout << "the trade-off parameter for fast decryption = " << pp.TRADEOFF_NUM << std::endl;
    pp.g.Print("pp.g"); 
    pp.h.Print("pp.h"); 
} 

void PrintCT(const CT &ct)
{
    ct.X.Print("CT.X");
    ct.Y.Print("CT.Y");
} 

void PrintCT(const MRCT &ct)
{
    std::string note;
    for(auto i = 0; i < ct.vec_X.size(); i++){
        note = "CT.X" + std::to_string(i);
        ct.vec_X[i].Print(note);
    }
    ct.Y.Print("CT.Y");
} 


std::string CTToByteString(CT &ct)
{
    std::string str = ct.X.ToByteString() + ct.Y.ToByteString(); 
    return str;
}


std::string MRCTToByteString(MRCT &ct)
{
    std::string str; 
    for(auto i = 0; i < ct.vec_X.size(); i++){
        str += ct.vec_X[i].ToByteString(); 
    }
    str += ct.Y.ToByteString(); 
    return str;
}


std::ofstream &operator<<(std::ofstream &fout, const TwistedElGamal::PP &pp)
{
    fout << pp.MSG_LEN << pp.TRADEOFF_NUM;
    fout << pp.MSG_SIZE; 
    fout << pp.g << pp.h; 
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, TwistedElGamal::PP &pp)
{
    fin >> pp.MSG_LEN >> pp.TRADEOFF_NUM; 
    fin >> pp.MSG_SIZE;
    fin >> pp.g >> pp.h; 
    return fin;
}

std::ofstream &operator<<(std::ofstream &fout, const CT &ct)
{
    fout << ct.X << ct.Y; 
    return fout; 
} 

std::ifstream &operator>>(std::ifstream &fin, CT &ct)
{
    fin >> ct.X >> ct.Y;
    return fin;  
} 

std::ofstream &operator<<(std::ofstream &fout, const MRCT &ct)
{
    fout << ct.vec_X << ct.Y; 
    return fout; 
} 

std::ifstream &operator>>(std::ifstream &fin, MRCT &ct)
{
    fin >> ct.vec_X >> ct.Y;
    return fin;  
} 



// core algorithms


/* Setup algorithm */ 
PP Setup(size_t MSG_LEN, size_t TRADEOFF_NUM)
{ 
    PP pp; 
    pp.MSG_LEN = MSG_LEN; 
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 
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

    return pp;
}


/* initialize the hashmap to accelerate decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize Twisted ElGamal PKE >>>" << std::endl; 

    CheckDlogParameters(pp.MSG_LEN, pp.TRADEOFF_NUM); 
 
    std::string table_filename = GetTableFileName(pp.h, pp.MSG_LEN, pp.TRADEOFF_NUM);      
    /* generate and save table */
    if(FileExist(table_filename) == false){
        std::cout << table_filename << " does not exist" << std::endl;
        BuildSaveTable(pp.h, pp.MSG_LEN, pp.TRADEOFF_NUM, table_filename);
    }
    
    // load the table from file 
    std::cout << table_filename << " already exists" << std::endl;
    LoadTable(table_filename, pp.MSG_LEN, pp.TRADEOFF_NUM); 
}

/* KeyGen algorithm */ 
std::tuple<ECPoint, BigInt> KeyGen(const PP &pp)
{ 
    BigInt sk = GenRandomBigIntLessThan(order); // sk \sample Z_p
    ECPoint pk = pp.g * sk; // pk = g^sk  

    #ifdef DEBUG
        std::cout << "key generation finished >>>" << std::endl;  
        pk.Print("pk"); 
        sk.Print("sk"); 
    #endif
    
    return {pk, sk}; 
}


/* Encryption algorithm: compute CT = Enc(pk, m; r) */ 
CT Enc(const PP &pp, const ECPoint &pk, const BigInt &m)
{ 
    CT ct;
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

    return ct;
}

/* Encryption algorithm: compute CT = Enc(pk, m; r): with explicit randomness */ 
CT Enc(const PP &pp, const ECPoint &pk, const BigInt &m, const BigInt &r)
{ 
    CT ct; 
    // begin encryption
    ct.X = pk * r; // X = pk^r
    
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_a{r, m};
    ct.Y = ECPointVectorMul(vec_A, vec_a); // CT.Y = pp.g * r + pp.h * m; 

    #ifdef DEBUG
        std::cout << "twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct; 
}

// add an method to encrypt message in G
CT Enc(const PP &pp, const ECPoint &pk, const ECPoint &m, const BigInt &r)
{ 
    CT ct; 
    // begin encryption
    ct.X = pk * r; // X = pk^r
    ct.Y = pp.g * r + m; // Y = g^r m
    return ct;
}


// add an method to decrypt message in G
ECPoint DecECPoint(const PP &pp, const BigInt &sk, const CT &ct)
{ 
    return ct.Y - ct.X * sk.ModInverse(order); 
}


/* Decryption algorithm: compute m = Dec(sk, CT) */ 
BigInt Dec(const PP &pp, const BigInt& sk, const CT &ct)
{ 
    BigInt m;
    //begin decryption  
    ECPoint M = ct.Y - ct.X * sk.ModInverse(order); // M = Y - X^{sk^{-1}} = h^m 

    bool SUCCESS = ShanksDLOG(pp.h, M, pp.MSG_LEN, pp.TRADEOFF_NUM, m); 
    if(SUCCESS == false)
    {
        std::cout << "decyption fails in the specified range" << std::endl; 
        exit(EXIT_FAILURE); 
    }  
    return m; 
}

/* 
** re-encrypt ciphertext CT with given randomness r 
** run by the secret key owner
*/ 
CT ReEnc(const PP &pp, const ECPoint &pk, const BigInt &sk, const CT &ct, const BigInt &r)
{ 
    CT ct_new; 
    // begin partial decryption  
    ECPoint M = ct.Y - ct.X * (sk.ModInverse(order)); // M = Y - X^{sk^{-1}} = h^m

    // begin re-encryption with the given randomness 
    ct_new.X = pk * r; // CT_new.X = pk^r 
    ct_new.Y = pp.g * r + M; // CT_new.Y = g^r 

    #ifdef DEBUG
        std::cout << "refresh ciphertext succeeds >>>"<< std::endl;
        PrintCT(ct_new); 
    #endif

    return ct_new;
}

/* 
** re-rand ciphertext CT  
** run by anyone
*/ 
CT ReRand(const PP &pp, const ECPoint &pk, const CT &ct)
{ 
    CT ct_new; 
    BigInt r = GenRandomBigIntLessThan(order); 

    // begin re-encryption with the given randomness 
    ct_new.X = ct.X + pk * r; // ct_new.X = ct.X + pk^r 
    ct_new.Y = ct.Y + pp.g * r; // ct_new.Y = ct.Y + g^r 

    #ifdef DEBUG
        std::cout << "rerand ciphertext succeeds >>>" << std::endl;
        PrintCT(ct_new); 
    #endif

    return ct_new;
}


/* homomorphic add */
CT HomoAdd(CT &ct1, CT &ct2)
{ 
    CT ct_result; 
    ct_result.X = ct1.X + ct2.X;  
    ct_result.Y = ct1.Y + ct2.Y;
    return ct_result;  
}

/* homomorphic sub */
CT HomoSub(CT &ct1, CT &ct2)
{ 
    CT ct_result; 
    ct_result.X = ct1.X - ct2.X;  
    ct_result.Y = ct1.Y - ct2.Y;
    return ct_result;   
}

/* scalar operation */
CT ScalarMul(CT &ct, const BigInt &k)
{ 
    CT ct_result;
    ct_result.X = ct.X * k;  
    ct_result.Y = ct.Y * k;
    return ct_result;   
}


/* 
* Encryption algorithm (2-recipients 1-message) with given random coins
* output X1 = pk1^r, X2 = pk2^r, Y = g^r h^m
* Here we make the randomness explict for the ease of generating the ZKP 
*/


MRCT Enc(const PP &pp, const std::vector<ECPoint> &vec_pk, const BigInt &m, const BigInt &r)
{  
    MRCT ct; 
    size_t n = vec_pk.size();
    for(auto i = 0; i < n; i++){
        ct.vec_X.emplace_back(vec_pk[i] * r); 
    }

    ct.Y = pp.g * r + pp.h * m; // Y = g^r h^m
   
    #ifdef DEBUG
        std::cout << n <<"-recipient 1-message twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct; 
}

}
# endif




