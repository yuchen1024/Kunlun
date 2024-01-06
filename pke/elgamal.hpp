#ifndef ELGAMAL_HPP_
#define ELGAMAL_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/ec_25519.hpp"
#include "../crypto/prg.hpp"
#include "../utility/print.hpp"

/*
 * x25519 NIKE protocol implies PKE, but x25519 is not full-fledged
 * the addition on EC curve is not well-defined
 * and thus does not obey distributive law w.r.t. exponentiation
 * therefore, it does not support re-randomization and homomorphic operations 
 * when you need re-randomizable PKE, you should disable X25519_ACCELERATION
*/

namespace ElGamal{
 
using Serialization::operator<<; 
using Serialization::operator>>; 

#ifndef ENABLE_X25519_ACCELERATION
// define the structure of PP
struct PP
{ 
    ECPoint g; // random generator 
};

// define the structure of ciphertext
struct CT
{
    ECPoint X; // X = g^r 
    ECPoint Y; // Y = pk^r + M  
};


std::ofstream &operator<<(std::ofstream &fout, const ElGamal::PP &pp)
{
    fout << pp.g; 
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, ElGamal::PP &pp)
{
    fin >> pp.g; 
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


// compare two ciphertexts
bool operator==(const CT& ct_left, const CT& ct_right)
{
    return (ct_left.X == ct_right.X) && (ct_left.Y == ct_right.Y);  
}

void PrintPP(const PP &pp)
{
    pp.g.Print("pp.g"); 
} 

void PrintCT(const CT &ct)
{
    ct.X.Print("CT.X");
    ct.Y.Print("CT.Y");
} 

// core algorithms

/* Setup algorithm */ 
PP Setup()
{ 
    PP pp; 
  
    pp.g = ECPoint(generator); 

    #ifdef PRINT
        std::cout << "generate the public parameters for ElGamal >>>" << std::endl; 
        PrintPP(pp); 
    #endif

    return pp;
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
CT Enc(const PP &pp, const ECPoint &pk, const ECPoint &m)
{ 
    CT ct;
    // generate the random coins 
    BigInt r = GenRandomBigIntLessThan(order); 

    // begin encryption
    ct.X = pp.g * r; // X = g^r
    ct.Y = pk * r + m;     // Y = pk^r g^m

    #ifdef DEBUG
        std::cout << "ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct;
}

/* Encryption algorithm: compute CT = Enc(pk, m; r): with explicit randomness */ 
CT Enc(const PP &pp, const ECPoint &pk, const ECPoint &m, const BigInt &r)
{ 
    CT ct; 
    // begin encryption
    ct.X = pp.g * r; // X = g^r
    ct.Y = pk * r + m; // Y = g^r m

    #ifdef DEBUG
        std::cout << "ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct; 
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
    ct_new.X = ct.X + pp.g * r; // ct_new.X = ct.X + g^r 
    ct_new.Y = ct.Y + pk * r; // ct_new.Y = ct.Y + pk^r 

    #ifdef DEBUG
        std::cout << "rerand ciphertext succeeds >>>" << std::endl;
        PrintCT(ct_new); 
    #endif

    return ct_new;
}

// decrypt 
ECPoint Dec(const PP &pp, const BigInt &sk, const CT &ct)
{ 
    return ct.Y - ct.X * sk; 
}


std::vector<unsigned char> CTtoByteArray(ElGamal::CT &ct)
{ 
    int thread_num = omp_get_thread_num();
	#ifdef ECPOINT_COMPRESSED
		std::vector<unsigned char> buffer(POINT_COMPRESSED_BYTE_LEN*2);
		EC_POINT_point2oct(group, ct.X.point_ptr, POINT_CONVERSION_COMPRESSED, buffer.data(), POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
        EC_POINT_point2oct(group, ct.Y.point_ptr, POINT_CONVERSION_COMPRESSED, buffer.data()+POINT_COMPRESSED_BYTE_LEN, POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
	#else
		std::vector<unsigned char> buffer(POINT_BYTE_LEN*2);
		EC_POINT_point2oct(group, ct.X.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer.data(), POINT_BYTE_LEN, bn_ctx[thread_num]);
        EC_POINT_point2oct(group, ct.Y.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer.data()+POINT_BYTE_LEN, POINT_BYTE_LEN, bn_ctx[thread_num]);
 
	#endif

    return buffer;            
}
 
ElGamal::CT ByteArraytoCT(std::vector<unsigned char> &buffer)
{ 
    ElGamal::CT ct; 
    int thread_num = omp_get_thread_num();
    #ifdef ECPOINT_COMPRESSED
        EC_POINT_oct2point(group, ct.X.point_ptr, buffer.data(), POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
        EC_POINT_oct2point(group, ct.Y.point_ptr, buffer.data()+POINT_COMPRESSED_BYTE_LEN, POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
    #else
        EC_POINT_oct2point(group, ct.X.point_ptr, buffer.data(), POINT_BYTE_LEN, bn_ctx[thread_num]); 
        EC_POINT_oct2point(group, ct.Y.point_ptr, buffer.data()+POINT_BYTE_LEN, POINT_BYTE_LEN, bn_ctx[thread_num]); 
    #endif
    
    return ct;            
}


#else
// define the structure of PP
struct PP
{ 
    EC25519Point g; // random generator 
};

// define the structure of ciphertext
struct CT
{
    EC25519Point X; // X = g^r 
    EC25519Point Y; // Y = pk^r + M  
};


std::ofstream &operator<<(std::ofstream &fout, const ElGamal::PP &pp)
{
    fout << pp.g; 
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, ElGamal::PP &pp)
{
    fin >> pp.g; 
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


void PrintPP(const PP &pp)
{
    pp.g.Print("pp.g"); 
} 

void PrintCT(const CT &ct)
{
    ct.X.Print("CT.X");
    ct.Y.Print("CT.Y");
} 

// core algorithms

/* Setup algorithm */ 
PP Setup()
{ 
    PP pp; 

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    GenRandomBytes(seed, pp.g.px, 32);  // pick a random generator

    #ifdef PRINT
        std::cout << "generate the public parameters for ElGamal >>>" << std::endl; 
        PrintPP(pp); 
    #endif

    return pp;
}


/* KeyGen algorithm */ 
std::tuple<EC25519Point, std::vector<uint8_t>> KeyGen(const PP &pp)
{ 
    std::vector<uint8_t> sk(32); 
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    GenRandomBytes(seed, sk.data(), 32);  // pick a random generator
    EC25519Point pk = pp.g * sk; // pk = g^sk  

    #ifdef PRINT
        std::cout << "key generation finished >>>" << std::endl;  
        pk.Print("pk"); 
        PrintBytes("sk", sk.data, 32); 
    #endif
    
    return {pk, sk}; 
}


/* Encryption algorithm: compute CT = Enc(pk, m; r) */ 
CT Enc(const PP &pp, const EC25519Point &pk, const EC25519Point &m)
{ 
    CT ct;
    // generate the random coins 
    std::vector<uint8_t> r(32); 
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    GenRandomBytes(seed, r.data(), 32);  // pick a random number

    // begin encryption
    ct.X = pp.g * r; // X = g^r
    ct.Y = pk * r ^ m; // Y = pk^r g^m

    #ifdef DEBUG
        std::cout << "ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct;
}

/* Encryption algorithm: compute CT = Enc(pk, m; r): with explicit randomness */ 
CT Enc(const PP &pp, const EC25519Point &pk, const EC25519Point &m, const std::vector<uint8_t> &r)
{ 
    CT ct; 
    // begin encryption
    ct.X = pp.g * r; // X = g^r
    ct.Y = pk * r ^ m; // Y = g^r m

    #ifdef DEBUG
        std::cout << "ElGamal encryption finishes >>>"<< std::endl;
        PrintCT(ct); 
    #endif

    return ct; 
}

// decrypt
EC25519Point Dec(const PP &pp, const std::vector<uint8_t> &sk, const CT &ct)
{ 
    return ct.Y ^ ct.X * sk; 
}
#endif

}

# endif




