/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************/
#ifndef KUNLUN_NIZK_DLOGEQ_HPP_
#define KUNLUN_NIZK_DLOGEQ_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"

namespace DLOGEquality{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of DLOG_EQ_Proof 
struct PP
{
    std::string ss_reserve;          // actually no pp here
};

struct Instance
{
    ECPoint g1, h1, g2, h2; 
}; 

struct Witness
{
    BigInt w; 
}; 

// define structure of DLOG_EQ_Proof 
struct Proof
{
    ECPoint A1, A2;     // P's first round message
    BigInt z;          // V's response
};


std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A1 << proof.A2 << proof.z;
    return fout;
} 

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A1 >> proof.A2 >> proof.z;
    return fin;
} 

void PrintInstance(Instance &instance)
{
    std::cout << "DLOG Equality Instance >>> " << std::endl; 
    instance.g1.Print("instance.g1"); 
    instance.h1.Print("instance.h1"); 
    instance.g2.Print("instance.g2"); 
    instance.h2.Print("instance.h2"); 
} 

void PrintWitness(Witness &witness)
{
    std::cout << "DLOG Equality Witness >>> " << std::endl; 
    witness.w.Print("w"); 
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for DLOG Equality >>> " << std::endl; 
    proof.A1.Print("proof.A1");
    proof.A2.Print("proof.A2");
    proof.z.Print("proof.z");
}

std::string ProofToByteString(Proof &proof)
{
    std::string str = proof.A1.ToByteString() + proof.A2.ToByteString() + proof.z.ToByteString();
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
    transcript_str += instance.g1.ToByteString() + instance.g2.ToByteString() 
                    + instance.h1.ToByteString() + instance.h2.ToByteString(); 
    // begin to generate proof
    BigInt a = GenRandomBigIntLessThan(BigInt(order)); // P's randomness used to generate A1, A2

    proof.A1 = instance.g1 * a; // A1 = g1^a
    proof.A2 = instance.g2 * a; // A2 = g2^a

    // update the transcript 
    transcript_str += proof.A1.ToByteString() + proof.A2.ToByteString(); 
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
    transcript_str += instance.g1.ToByteString() + instance.g2.ToByteString() 
                    + instance.h1.ToByteString() + instance.h2.ToByteString(); 

    // update the transcript 
    transcript_str += proof.A1.ToByteString() + proof.A2.ToByteString(); 
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // V's challenge in Zq; 

    bool condition1, condition2; 

    ECPoint LEFT, RIGHT;
    LEFT = instance.g1 * proof.z; // LEFT = g1^z
    RIGHT = proof.A1 + instance.h1 * e;  // RIGHT = A1 h1^e  

    condition1 = (LEFT==RIGHT); //check g1^z = A1 h1^e
    
    // check condition 2
    LEFT = instance.g2 * proof.z; // LEFT = g2^z
    RIGHT = proof.A2 + instance.h2 * e;  // RIGHT = A2 h2^e    

    condition2 = (LEFT==RIGHT); //check g2^z = A2 h2^e

    bool Validity = condition1 && condition2; 

    #ifdef DEBUG
        PrintSplitLine('-'); 
        std::cout << std::boolalpha << "Condition 1 (LOG_EQ Proof) = " << condition1 << std::endl; 
        std::cout << std::boolalpha << "Condition 2 (LOG_EQ Proof) = " << condition2 << std::endl;
        if (Validity){ 
            std::cout<< "DLOG Equality Proof Accepts >>>" << std::endl; 
        }
        else{
            std::cout<< "DLOG Equality Proof Rejects >>>" << std::endl; 
        }
    #endif

    return Validity;
}



}
#endif