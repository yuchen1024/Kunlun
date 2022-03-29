#ifndef SCHNORR_HPP_
#define SCHNORR_HPP_

#include "../crypto/global.hpp"
#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../utility/routines.hpp"

namespace Schnorr{

// define the structure of PP
struct PP
{  
    ECPoint g; 
};


// define keypair 
struct Schnorr_KP
{
    EC_POINT *pk; // define pk
    BIGNUM *sk;   // define sk
};

// define signature 
struct SIG
{
    ECPoint A; 
    BigInt z;
};


/* Setup algorithm */
PP Setup()
{
    PP pp; 
    pp.g = ECPoint(generator); 
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


/* This function takes as input a message, returns a signature. */
SIG Sign(const PP &pp, const BigInt &sk, const std::string &message)
{
    SIG sigma; // define the signature
    BigInt r = GenRandomBigIntLessThan(order);
    sigma.A = pp.g*r; 


    // compute e = H(A||m)
    BigInt e = Hash::StringToBigInt(sigma.A.ToByteString() + message);
    sigma.z = (r + sk*e) % order; // z = (r+sk*e) mod order 

    #ifdef DEBUG
        std::cout << "Schnorr signature generation finishes >>>" << std::endl;
        PrintSIG(sigma);  
    #endif

    return sigma; 
}


/* This function verifies validity of (sig, message) */
bool Verify(const PP &pp, const ECPoint &pk, std::string &message, SIG &sigma)
{
    bool Validity;       

    // compute e = H(A||m)
    // compute e = H(A||m)
    BigInt e = Hash::StringToBigInt(sigma.A.ToByteString() + message);

    ECPoint LEFT = pp.g*sigma.z; // LEFT = g^z 
    ECPoint RIGHT = pk*e + sigma.A;   // RIGHT = pk^e + A

    if(LEFT == RIGHT) Validity = true; 
    else Validity = false; 
 
    #ifdef DEBUG
    if (Validity)
    {
        std::cout << "signature is valid >>>" << std::endl;
    }
    else
    {
        std::cout << "signature is invalid >>>" << std::endl;
    }
    #endif

    return Validity;
}

void SerializePP(PP &pp, std::ofstream &fout)
{
    fout << pp.g; 
}

void DeserializePP(PP &pp, std::ifstream &fin)
{
    fin >> pp.g; 
}

void PrintPP(PP &pp)
{
    pp.g.Print("pp.g"); 
} 

void PrintSIG(SIG &sig)
{
    sig.A.Print("sig.A");
    sig.z.Print("sig.z");
} 

void SerializeSIG(SIG &sigma, std::ofstream &fout)
{
    fout << sigma.A; 
    fout << sigma.z; 
} 

void DeserializeSIG(SIG &sigma, std::ifstream &fin)
{
    fin >> sigma.A; 
    fin >> sigma.z; 
}
 
}

#endif