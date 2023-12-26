/****************************************************************************
this hpp implements NIZKPoK for twisted ElGamal ciphertext 
*****************************************************************************/
#ifndef KUNLUN_NIZK_PTKE_HPP_
#define KUNLUN_NIZK_PTKE_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/twisted_exponential_elgamal.hpp"

namespace PlaintextKnowledge{
// define structure of PT_EQ_Proof

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    ECPoint g; 
    ECPoint h; 
};

// structure of instance 
struct Instance
{
    ECPoint pk; 
    TwistedExponentialElGamal::CT ct; 
};

// structure of witness 
struct Witness
{
    BigInt v; 
    BigInt r; 
};

// structure of proof 
struct Proof
{
    ECPoint A, B; // P's first round message
    BigInt z1, z2;  // P's response in Zq
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A << proof.B << proof.z1 << proof.z2;
    return fout;  
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A >> proof.B >> proof.z1 >> proof.z2; 
    return fin; 
}


void PrintInstance(Instance &instance)
{
    std::cout << "Plaintext Knowledge Instance >>> " << std::endl; 
    instance.pk.Print("instance.pk"); 
    instance.ct.X.Print("instance.X"); 
    instance.ct.Y.Print("instance.Y"); 
} 

void PrintWitness(Witness &witness)
{
    std::cout << "Plaintext Knowledge Witness >>> " << std::endl; 
    witness.v.Print("witness.v"); 
    witness.r.Print("witness.r"); 
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for Plaintext Knowledge >>> " << std::endl; 

    proof.A.Print("proof.A"); 
    proof.B.Print("proof.B"); 
    proof.z1.Print("proof.z1");
    proof.z2.Print("proof.z2"); 
}

std::string ProofToByteString(Proof &proof)
{
    std::string str = proof.A.ToByteString() + proof.B.ToByteString() + proof.z1.ToByteString() + proof.z2.ToByteString();
    return str;  
}


/*  Setup algorithm */
PP Setup(TwistedExponentialElGamal::PP pp_enc)
{ 
    PP pp;
    pp.g = pp_enc.g;
    pp.h = pp_enc.h; 

    #ifdef DEBUG
        std::cout << "generate public parameters of NIZK for plaintext knowledge >>>" << std::endl; 
        pp.g.Print("pp.g"); 
        pp.h.Print("pp.h"); 
    #endif

    return pp; 
}


// generate NIZK proof for C = Enc(pk, v; r) with witness (r, v)
Proof Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str)
{   
    Proof proof;
    // initialize the transcript with instance 
    transcript_str += instance.pk.ToByteString() + instance.ct.X.ToByteString() + instance.ct.Y.ToByteString(); 
    
    BigInt a = GenRandomBigIntLessThan(order); 
    proof.A = instance.pk * a; // A = pk^a

    BigInt b = GenRandomBigIntLessThan(order); 


    std::vector<ECPoint> vec_base{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{a, b};
    proof.B = ECPointVectorMul(vec_base, vec_x); // B = g^a h^b

    // update the transcript with the first round message
    transcript_str += proof.A.ToByteString() + proof.B.ToByteString(); 

    // computer the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // V's challenge in Zq: apply FS-transform to generate the challenge
    
    // compute the response 
    proof.z1 = (a + e * witness.r) % order; // z1 = a+e*r mod q
    proof.z2 = (b + e * witness.v) % order; // z2 = b+e*v mod q

    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof;
}


// check NIZKPoK for C = Enc(pk, v; r) 
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{    
    // initialize the transcript with instance 
    transcript_str += instance.pk.ToByteString() + instance.ct.X.ToByteString() + instance.ct.Y.ToByteString(); 

    // update the transcript with the first round message
    transcript_str += proof.A.ToByteString() + proof.B.ToByteString(); 
    
    // recover the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    std::vector<bool> vec_condition(2); 
    ECPoint LEFT, RIGHT;

    // check condition 1
    LEFT = instance.pk * proof.z1; // // LEFT  = pk^z1
    RIGHT = proof.A + instance.ct.X * e; // RIGHT = A X^e

    vec_condition[0] = (LEFT == RIGHT); //check pk^z1 = A X^e
    
    // check condition 2
    std::vector<ECPoint> vec_base{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{proof.z1, proof.z2}; 
    LEFT = ECPointVectorMul(vec_base, vec_x); // LEFT = g^z1 h^z2
    RIGHT = proof.B + instance.ct.Y * e; // RIGHT = B Y^e 

    vec_condition[1] = (LEFT == RIGHT); //check g^z1 h^z2 = B Y^e

    bool Validity = vec_condition[0] && vec_condition[1];

    #ifdef DEBUG
    PrintSplitLine('-'); 
    std::cout << "verify the NIZKPoK for [twisted ElGamal plaintext/randomness knowledge] >>>" << std::endl; 
    for(auto i = 0; i < vec_condition.size(); i++){
        std::cout << std::boolalpha << "Condition " << i << " (Plaintext Knowledge proof) = " 
                                    << vec_condition[i] << std::endl; 
    }
    if (Validity) { 
        std::cout << "NIZKPoK for [twisted ElGamal plaintext/randomness knowledge] accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZKPoK for [twisted ElGamal plaintext/randomness knowledge] rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}



}
#endif
