/****************************************************************************
this hpp implements NIZKPoK for twisted ElGamal ciphertext 
*****************************************************************************/
#ifndef NIZK_PTKE_HPP_
#define NIZK_PTKE_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define structure of PT_EQ_Proof 
struct Plaintext_Knowledge_PP
{
    ECPoint g; 
    ECPoint h; 
};

// structure of instance 
struct Plaintext_Knowledge_Instance
{
    ECPoint pk; 
    ECPoint X; 
    ECPoint Y; 
};

// structure of witness 
struct Plaintext_Knowledge_Witness
{
    BigInt v; 
    BigInt r; 
};

// structure of proof 
struct Plaintext_Knowledge_Proof
{
    ECPoint A, B; // P's first round message
    BigInt z1, z2;  // P's response in Zq
};


void Plaintext_Knowledge_Print_Instance(Plaintext_Knowledge_Instance &instance)
{
    std::cout << "Plaintext Knowledge Instance >>> " << std::endl; 
    instance.pk.Print("instance.pk"); 
    instance.X.Print("instance.X"); 
    instance.Y.Print("instance.Y"); 
} 

void Plaintext_Knowledge_Print_Witness(Plaintext_Knowledge_Witness &witness)
{
    std::cout << "Plaintext Knowledge Witness >>> " << std::endl; 
    witness.v.Print("witness.v"); 
    witness.r.Print("witness.r"); 
} 

void Plaintext_Knowledge_Print_Proof(Plaintext_Knowledge_Proof &proof)
{
    Print_SplitLine('-'); 
    std::cout << "NIZKPoK for Plaintext Knowledge >>> " << std::endl; 

    proof.A.Print("proof.A"); 
    proof.B.Print("proof.B"); 
    proof.z1.Print("proof.z1");
    proof.z2.Print("proof.z2"); 
} 

void Plaintext_Knowledge_Serialize_Proof(Plaintext_Knowledge_Proof &proof, std::ofstream &fout)
{
    fout << proof.A << proof.B << proof.z1 << proof.z2; 
}

void Plaintext_Knowledge_Deserialize_Proof(Plaintext_Knowledge_Proof &proof, std::ifstream &fin)
{
    fin >> proof.A >> proof.B >> proof.z1 >> proof.z2; 
}

/*  Setup algorithm */
void NIZK_Plaintext_Knowledge_Setup(Plaintext_Knowledge_PP &pp)
{ 
    pp.g = generator;
    pp.h = HashToPoint(ECPointToByteString(pp.g)); 

    #ifdef DEBUG
    std::cout << "generate public parameters of NIZK for plaintext knowledge >>>" << std::endl; 
    pp.g.Print("pp.g"); 
    pp.h.Print("pp.h"); 
    #endif
}



// generate NIZK proof for C = Enc(pk, v; r) with witness (r, v)
void NIZK_Plaintext_Knowledge_Prove(Plaintext_Knowledge_PP &pp, 
                                    Plaintext_Knowledge_Instance &instance, 
                                    Plaintext_Knowledge_Witness &witness, 
                                    std::string &transcript_str,
                                    Plaintext_Knowledge_Proof &proof)
{   
    // initialize the transcript with instance 
    transcript_str += ECPointToByteString(instance.pk) + ECPointToByteString(instance.X) + 
                      ECPointToByteString(instance.Y); 
    
    BigInt a = GenRandomBigIntLessThan(order); 
    proof.A = instance.pk * a; // A = pk^a

    BigInt b = GenRandomBigIntLessThan(order); 


    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{a, b};
    proof.B = ECPointVector_Mul(vec_A, vec_x); // B = g^a h^b

    // update the transcript with the first round message
    transcript_str += ECPointToByteString(proof.A) + ECPointToByteString(proof.B); 

    // computer the challenge
    BigInt e = HashToBigInt(transcript_str); // V's challenge in Zq: apply FS-transform to generate the challenge
    
    // compute the response 
    proof.z1 = (a + e * witness.r) % order; // z1 = a+e*r mod q
    proof.z2 = (b + e * witness.v) % order; // z2 = b+e*v mod q

    #ifdef DEBUG
    Plaintext_Knowledge_Print_Proof(proof); 
    #endif
}


// check NIZKPoK for C = Enc(pk, v; r) 
bool NIZK_Plaintext_Knowledge_Verify(Plaintext_Knowledge_PP &pp, 
                                     Plaintext_Knowledge_Instance &instance, 
                                     std::string &transcript_str, 
                                     Plaintext_Knowledge_Proof &proof)
{    
    // initialize the transcript with instance 
    transcript_str += ECPointToByteString(instance.pk) + ECPointToByteString(instance.X) + 
                      ECPointToByteString(instance.Y); 

    // update the transcript with the first round message
    transcript_str += ECPointToByteString(proof.A) + ECPointToByteString(proof.B); 
    
    // recover the challenge
    BigInt e = HashToBigInt(transcript_str); // apply FS-transform to generate the challenge

    bool V1, V2; 
    ECPoint LEFT, RIGHT;

    // check condition 1
    LEFT = instance.pk * proof.z1; // // LEFT  = pk^z1
    RIGHT = proof.A + instance.X * e; // RIGHT = A X^e

    V1 = (LEFT == RIGHT); //check pk^z1 = A X^e
    
    // check condition 2
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{proof.z1, proof.z2}; 
    LEFT = ECPointVector_Mul(vec_A, vec_x); // LEFT = g^z1 h^z2
    RIGHT = proof.B + instance.Y * e; // RIGHT = B Y^e 

    V2 = (LEFT == RIGHT); //check g^z1 h^z2 = B Y^e

    bool Validity = V1 && V2;

    #ifdef DEBUG
    Print_SplitLine('-'); 
    std::cout << "verify the NIZKPoK for plaintext knowledge >>>" << std::endl; 
    std::cout << std::boolalpha << "Condition 1 (Plaintext Knowledge proof) = " << V1 << std::endl; 
    std::cout << std::boolalpha << "Condition 2 (Plaintext Knowledge proof) = " << V2 << std::endl; 
    if (Validity) { 
        std::cout << "NIZKPoK for twisted ElGamal ciphertext accepts >>>" << std::endl; 
    } else {
        std::cout<< "NIZKPoK for twisted ElGamal ciphertext rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}

#endif
