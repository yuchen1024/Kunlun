/***********************************************************************************
this hpp implements NIZKPoK for three twisited ElGamal ciphertexts 
(randomness reuse) encrypt the same message 
***********************************************************************************/
#ifndef KUNLUN_NIZK_PTEQ_HPP_
#define KUNLUN_NIZK_PTEQ_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/twisted_exponential_elgamal.hpp"

namespace PlaintextEquality{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of PT_EQ_Proof 
struct PP
{
    ECPoint g; 
    ECPoint h;
};

// structure of instance (pk_1,...,pk_n, Xi = pk_i^r, Y = g^r h^v)
struct Instance
{
    std::vector<ECPoint> vec_pk; 
    TwistedExponentialElGamal::MRCT ct;  
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
    std::vector<ECPoint> vec_A; 
    ECPoint B; // P's first round message
    BigInt z, t;    // P's response in Zq
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.vec_A; 
    fout << proof.B << proof.z << proof.t; 
    return fout;
} 

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.vec_A; 
    fin >> proof.B >> proof.z >> proof.t; 
    return fin;
} 



void PrintInstance(Instance &instance)
{
    std::cout << "Plaintext Equality Instance >>> " << std::endl; 
    std::string note; 
    for(auto i = 0; i < instance.vec_pk.size(); i++){
        note = "instance.pk" + std::to_string(i);
        instance.vec_pk[i].Print(note); 
    }

    for(auto i = 0; i < instance.ct.vec_X.size(); i++){
        note = "instance.X" + std::to_string(i);
        instance.ct.vec_X[i].Print(note); 
    }

    instance.ct.Y.Print("instance.Y"); 
} 

void PrintWitness(Witness &witness)
{
    std::cout << "Plaintext Equality Witness >>> " << std::endl; 
    witness.v.Print("witness.v"); 
    witness.r.Print("witness.r"); 
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for Plaintext Equality >>> " << std::endl; 

    std::string note;
    for(auto i = 0; i < proof.vec_A.size(); i++){
        note = "proof.A" + std::to_string(i);
        proof.vec_A[i].Print(note); 
    }
    proof.B.Print("proof.B"); 
    proof.z.Print("proof.z"); 
    proof.t.Print("proof.t"); 
} 

std::string ProofToByteString(Proof &proof)
{
    std::string str;
    for(auto i = 0; i < proof.vec_A.size(); i++){
        str += proof.vec_A[i].ToByteString();
    }
    proof.B.ToByteString(); 
    proof.z.ToByteString(); 
    proof.t.ToByteString(); 
    return str; 
} 


/* Setup algorithm */ 
PP Setup(TwistedExponentialElGamal::PP pp_enc)
{ 
    PP pp;
    pp.g = pp_enc.g;
    pp.h = pp_enc.h; 
    return pp;
}

// generate NIZK proof for Ci = Enc(pki, v; r) i={1,2,3} the witness is (r, v)
Proof Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str)
{    
    Proof proof; 
    // initialize the transcript with instance
    for(auto i = 0; i < instance.vec_pk.size(); i++){
        transcript_str += instance.vec_pk[i].ToByteString();
    }

    for(auto i = 0; i < instance.vec_pk.size(); i++){
        transcript_str += instance.ct.vec_X[i].ToByteString();
    } 

    transcript_str += instance.ct.Y.ToByteString(); 

    BigInt a = GenRandomBigIntLessThan(order);
    size_t n = instance.vec_pk.size();
    proof.vec_A.resize(n); 
    for(auto i = 0; i < proof.vec_A.size(); i++){
        proof.vec_A[i] = instance.vec_pk[i] * a;
    }

    BigInt b = GenRandomBigIntLessThan(order); 
    std::vector<ECPoint> vec_Base{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{a, b};
    proof.B = ECPointVectorMul(vec_Base, vec_x); // B = g^a h^b

    // update the transcript with the first round message
    for(auto i = 0; i < instance.vec_pk.size(); i++){
        transcript_str += proof.vec_A[i].ToByteString();
    } 
    transcript_str += proof.B.ToByteString();  
                     
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    // compute the response 
    proof.z = (a + e * witness.r) % order; // z = a+e*r mod q 
    proof.t = (b + e * witness.v) % order; // t = b+e*v mod q

    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof; 
}


// check NIZK proof PI for Ci = Enc(pki, m; r) the witness is (r1, r2, m)
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    // initialize the transcript with instance
    for(auto i = 0; i < instance.vec_pk.size(); i++){
        transcript_str += instance.vec_pk[i].ToByteString();
    }

    for(auto i = 0; i < instance.vec_pk.size(); i++){
        transcript_str += instance.ct.vec_X[i].ToByteString();
    } 

    transcript_str += instance.ct.Y.ToByteString(); 

    for(auto i = 0; i < instance.vec_pk.size(); i++){
        transcript_str += proof.vec_A[i].ToByteString();
    } 
    transcript_str += proof.B.ToByteString();  
    
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    size_t n = instance.vec_pk.size();
    std::vector<bool> vec_condition(n+1);

    ECPoint LEFT, RIGHT; 

    for(auto i = 0; i < n; i++){
        LEFT = instance.vec_pk[i] * proof.z; // pk1^{z}
        RIGHT = proof.vec_A[i] + instance.ct.vec_X[i] * e;  
        vec_condition[i] = (LEFT == RIGHT); //check pk1^z = A1 X1^e
    }

    // check condition 4
    std::vector<ECPoint> vec_base{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{proof.z, proof.t}; 
    LEFT = ECPointVectorMul(vec_base, vec_x); // g^z h^t
    RIGHT = proof.B + instance.ct.Y * e; // B Y^e
    
    vec_condition[n] = (LEFT == RIGHT); // check g^z h^t = B Y^e

    bool Validity = true; 
    for(auto i = 0; i <=n ; i++){
        if(vec_condition[i] == false) Validity = false;
    }

    #ifdef DEBUG
    for(auto i = 0; i <=n; i++){
        std::cout << std::boolalpha << "Condition "<< std::to_string(i) <<" (Plaintext Equality proof) = " 
                  << vec_condition[i] << std::endl; 
    }

    if (Validity){ 
        std::cout << "NIZK proof for " << std::to_string(n) 
                  << "-receivers twisted ElGamal plaintext equality accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZK proof for " << std::to_string(n) 
                  << "-receivers twisted ElGamal plaintext equality rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}



}

#endif



