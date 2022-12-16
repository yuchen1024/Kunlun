/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************/
#ifndef KUNLUN_NIZK_DLOG_KNOWLEDGE_HPP_
#define KUNLUN_NIZK_DLOG_KNOWLEDGE_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"

namespace DLOGKnowledge{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of DLOG_EQ_Proof 
struct PP
{
    std::string ss_reserve;          // actually no pp here
};

struct Instance
{
    ECPoint g, h; 
}; 

struct Witness
{
    BigInt w; 
}; 

// define structure of DLOG_EQ_Proof 
struct Proof
{
    ECPoint A;     // P's first round message
    BigInt z;          // V's response
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A << proof.z;
    return fout; 
} 

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A >> proof.z;
    return fin; 
} 

void PrintInstance(Instance &instance)
{
    std::cout << "DLOG Knowledge Instance >>> " << std::endl; 
    instance.g.Print("instance.g"); 
    instance.h.Print("instance.h"); 
} 

void PrintWitness(Witness &witness)
{
    std::cout << "DLOG Knowledge Witness >>> " << std::endl; 
    witness.w.Print("w"); 
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for DLOG Knowledge >>> " << std::endl; 
    proof.A.Print("proof.A");
    proof.z.Print("proof.z");
}

std::string ProofToByteString(Proof &proof)
{
    std::string str = proof.A.ToByteString() + proof.z.ToByteString(); 
    return str;
}


/* Setup algorithm: do nothing */ 
PP Setup()
{ 
    PP pp;
    pp.ss_reserve = "dummy";
    return pp;  
}


// Generate a NIZK proof PI for g1^w = h1 and g2^w = h2
Proof Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str)
{
    Proof proof; 
    // initialize the transcript with instance 
    transcript_str += instance.g.ToByteString() + instance.h.ToByteString(); 
    // begin to generate proof
    BigInt a = GenRandomBigIntLessThan(BigInt(order)); // P's randomness used to generate A1, A2

    proof.A = instance.g * a; // A = g1^r

    // update the transcript 
    transcript_str += proof.A.ToByteString(); 
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // V's challenge in Zq; 

    // compute the response
    proof.z = (a + e * witness.w) % order; // z = a+e*w mod q

    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof; 
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    // initialize the transcript with instance 
    transcript_str += instance.g.ToByteString() + instance.h.ToByteString(); 

    // update the transcript 
    transcript_str += proof.A.ToByteString(); 
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // V's challenge in Zq; 

    
    ECPoint LEFT, RIGHT;
    LEFT = instance.g * proof.z; // LEFT = g^z
    RIGHT = proof.A + instance.h * e;  // RIGHT = A h^e  

    bool Validity = (LEFT==RIGHT); //check g^z = A h^e 

    #ifdef DEBUG
        PrintSplitLine('-');  
        if (Validity){ 
            std::cout<< "DLOG Knowledge Proof Accepts >>>" << std::endl; 
        }
        else{
            std::cout<< "DLOG Knowledge Proof Rejects >>>" << std::endl; 
        }
    #endif

    return Validity;
}


}
#endif