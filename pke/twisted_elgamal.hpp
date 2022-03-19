#ifndef TWISTED_ELGAMAL_HPP_
#define TWISTED_ELGAMAL_HPP_

#include "../crypto/global.hpp"
#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../utility/routines.hpp"
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


void PrintPP(const PP &pp)
{
    std::cout << "the length of message space = " << pp.MSG_LEN << std::endl; 
    std::cout << "the trade-off parameter for fast decryption = " << pp.TRADEOFF_NUM << std::endl;
    std::cout << "the optimal decryption thread num = " << pp.DEC_THREAD_NUM << std::endl;
    pp.g.Print("pp.g"); 
    pp.h.Print("pp.h"); 
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

std::string CTToByteString(CT &ct)
{
    std::string str = ct.X.ToByteString() + ct.Y.ToByteString(); 
    return str;
}


/* Setup algorithm */ 
PP Setup(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t DEC_THREAD_NUM)
{ 
    PP pp; 
    pp.MSG_LEN = MSG_LEN; 
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 
    pp.DEC_THREAD_NUM = DEC_THREAD_NUM;
    /* set the message space to 2^{MSG_LEN} */
    pp.MSG_SIZE = BigInt(size_t(pow(2, pp.MSG_LEN))); 

    #ifdef PRINT
        std::cout << "message space = [0, ";   
        std::cout << BN_bn2hex(pp.MSG_SIZE.bn_ptr) << ')' << std::endl; 
    #endif
  
    pp.g = ECPoint(generator); 

    /* generate pp.h via deterministic and transparent manner */
    pp.h = Hash::StringToECPoint(pp.g.ToByteString());   

    #ifdef PRINT
        std::cout << "generate the public parameters for twisted ElGamal >>>" << std::endl; 
        PrintPP(pp); 
    #endif

    return pp;
}

void SerializePP(PP &pp, std::ofstream &fout)
{
    fout.write((char *)(&pp.MSG_LEN), sizeof(pp.MSG_LEN));
    fout.write((char *)(&pp.TRADEOFF_NUM), sizeof(pp.TRADEOFF_NUM));
    fout.write((char *)(&pp.DEC_THREAD_NUM), sizeof(pp.DEC_THREAD_NUM));

    fout << pp.MSG_SIZE; 
    fout << pp.g;
    fout << pp.h; 
}

void DeserializePP(PP &pp, std::ifstream &fin)
{
    fin.read((char *)(&pp.MSG_LEN), sizeof(pp.MSG_LEN));
    fin.read((char *)(&pp.TRADEOFF_NUM), sizeof(pp.TRADEOFF_NUM));
    fin.read((char *)(&pp.DEC_THREAD_NUM), sizeof(pp.DEC_THREAD_NUM));

    fin >> pp.MSG_SIZE; 
    fin >> pp.g;
    fin >> pp.h; 
}



/* initialize the hashmap to accelerate decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize Twisted ElGamal PKE >>>" << std::endl; 

    CheckDlogParameters(pp.MSG_LEN, pp.TRADEOFF_NUM, pp.DEC_THREAD_NUM); 
 
    std::string keytable_filename = GetKeyTableFileName(pp.h, pp.MSG_LEN, pp.TRADEOFF_NUM);     
    /* generate babystep table */
    if(FileExist(keytable_filename) == false){
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
std::tuple<ECPoint, BigInt> KeyGen(const PP &pp)
{ 
    BigInt sk = GenRandomBigIntLessThan(order); // sk \sample Z_p
    ECPoint pk = pp.g * sk; // pk = g^sk  

    #ifdef PRINT
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
    //CT.Y = pp.g * r + pp.h * m; // Y = g^r h^m
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_a{r, m};
    ct.Y = ECPointVectorMul(vec_A, vec_a); 

    #ifdef DEBUG
        std::cout << "twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct; 
}

// add an method to encrypt message in G
CT EncECPoint(const PP &pp, const ECPoint &pk, const ECPoint &m, const BigInt &r)
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
    return m; 
}



/* re-encrypt ciphertext CT with given randomness r */ 
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

void PrintCT(const MRCT &ct)
{
    std::string note;
    for(auto i = 0; i < ct.vec_X.size(); i++){
        note = "CT.X" + std::to_string(i);
        ct.vec_X[i].Print(note);
    }
    ct.Y.Print("CT.Y");
} 

MRCT Enc(const PP &pp, const std::vector<ECPoint> &vec_pk, const BigInt &m, const BigInt &r)
{  
    MRCT ct; 
    size_t n = vec_pk.size();
    for(auto i = 0; i < n; i++){
        ct.vec_X.push_back(vec_pk[i] * r); 
    }
 
    ct.Y = pp.g * r + pp.h * m; // Y = g^r h^m
   
    #ifdef DEBUG
        std::cout << n <<"-recipient 1-message twisted ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct; 
}

void SerializeCT(MRCT &ct, std::ofstream& fout)
{
    for(auto i = 0; i < ct.vec_X.size(); i++){
        ct.vec_X[i].Serialize(fout); 
    }
    ct.Y.Serialize(fout); 
} 

void DeserializeCT(MRCT &ct, std::ifstream& fin)
{
    for(auto i = 0; i < ct.vec_X.size(); i++){
        ct.vec_X[i].Deserialize(fin); 
    }
    ct.Y.Deserialize(fin); 
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


bool operator==(const CT& ct_left, const CT& ct_right)
{
    return (ct_left.X == ct_right.X) && (ct_left.Y == ct_right.Y);  
}

}
# endif




