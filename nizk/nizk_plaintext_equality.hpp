/***********************************************************************************
this hpp implements NIZKPoK for three twisited ElGamal ciphertexts 
(randomness reuse) encrypt the same message 
***********************************************************************************/
#ifndef NIZK_PTEQ_HPP_
#define NIZK_PTEQ_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/bigint.hpp"
#include "../crypto/hash.hpp"
#include "../common/routines.hpp"
#include "../common/print.hpp"

// define structure of PT_EQ_Proof 
struct Plaintext_Equality_PP
{
    ECPoint g; 
    ECPoint h; 
};

// structure of instance
struct Plaintext_Equality_Instance
{
    ECPoint pk1, pk2, pk3; 
    ECPoint X1, X2, X3, Y; 
};

// structure of witness 
struct Plaintext_Equality_Witness
{
    BigInt v; 
    BigInt r; 
};


// structure of proof 
struct Plaintext_Equality_Proof
{
    ECPoint A1, A2, A3, B; // P's first round message
    BigInt z, t;    // P's response in Zq
};



void Plaintext_Equality_Print_Instance(Plaintext_Equality_Instance &instance)
{
    std::cout << "Plaintext Equality Instance >>> " << std::endl; 
    instance.pk1.Print("instance.pk1"); 
    instance.pk2.Print("instance.pk2"); 
    instance.pk3.Print("instance.pk3"); 
    instance.X1.Print("instance.X1"); 
    instance.X2.Print("instance.X2"); 
    instance.X3.Print("instance.X3"); 
    instance.Y.Print("instance.Y"); 
} 

void Plaintext_Equality_Print_Witness(Plaintext_Equality_Witness &witness)
{
    std::cout << "Plaintext Equality Witness >>> " << std::endl; 
    witness.v.Print("witness.v"); 
    witness.r.Print("witness.r"); 
} 

void Plaintext_Equality_Print_Proof(Plaintext_Equality_Proof &proof)
{
    Print_SplitLine('-'); 
    std::cout << "NIZKPoK for Plaintext Equality >>> " << std::endl; 
    proof.A1.Print("proof.A1"); 
    proof.A2.Print("proof.A2"); 
    proof.A3.Print("proof.A3"); 
    proof.B.Print("proof.B"); 
    proof.z.Print("proof.z"); 
    proof.t.Print("proof.t"); 
} 

void Plaintext_Equality_Serialize_Proof(Plaintext_Equality_Proof &proof, std::ofstream &fout)
{
    fout << proof.A1 << proof.A2 << proof.A3 << proof.B << proof.z << proof.t; 
} 

void Plaintext_Equality_Deserialize_Proof(Plaintext_Equality_Proof &proof, std::ifstream &fin)
{
    fin >> proof.A1 >> proof.A2 >> proof.A3 >> proof.B >> proof.z >> proof.t; 
} 

/* Setup algorithm */ 
void NIZK_Plaintext_Equality_Setup(Plaintext_Equality_PP &pp)
{ 
    pp.g = generator; 
    pp.h = HashToPoint(ECPointToByteString(pp.g));  
}

// generate NIZK proof for Ci = Enc(pki, v; r) i={1,2,3} the witness is (r, v)
void NIZK_Plaintext_Equality_Prove(Plaintext_Equality_PP &pp, 
                                   Plaintext_Equality_Instance &instance, 
                                   Plaintext_Equality_Witness &witness, 
                                   std::string &transcript_str, 
                                   Plaintext_Equality_Proof &proof)
{    
    // initialize the transcript with instance 
    transcript_str += ECPointToByteString(instance.pk1) + ECPointToByteString(instance.pk2)  
                    + ECPointToByteString(instance.pk3) + ECPointToByteString(instance.X1)   
                    + ECPointToByteString(instance.X2)  + ECPointToByteString(instance.X3)
                    + ECPointToByteString(instance.Y); 

    BigInt a = GenRandomBigIntLessThan(order); 
    proof.A1 = instance.pk1 * a; // A1 = pk1^a
    proof.A2 = instance.pk2 * a; // A2 = pk2^a
    proof.A3 = instance.pk3 * a; // A3 = pk3^a

    BigInt b = GenRandomBigIntLessThan(order); 
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{a, b};
    proof.B = ECPointVector_Mul(vec_A, vec_x); // B = g^a h^b

    // update the transcript with the first round message
    transcript_str += ECPointToByteString(proof.A1) + ECPointToByteString(proof.A2) 
                    + ECPointToByteString(proof.A3) + ECPointToByteString(proof.B);  
    // compute the challenge
    BigInt e = HashToBigInt(transcript_str); // apply FS-transform to generate the challenge

    // compute the response 
    proof.z = (a + e * witness.r) % order; // z = a+e*r mod q 
    proof.t = (b + e * witness.v) % order; // t = b+e*v mod q

    #ifdef DEBUG
    Plaintext_Equality_Print_Proof(proof); 
    #endif
}


// check NIZK proof PI for Ci = Enc(pki, m; r) the witness is (r1, r2, m)
bool NIZK_Plaintext_Equality_Verify(Plaintext_Equality_PP &pp, 
                                    Plaintext_Equality_Instance &instance, 
                                    std::string &transcript_str,
                                    Plaintext_Equality_Proof &proof)
{
    // initialize the transcript with instance 
    transcript_str += ECPointToByteString(instance.pk1) + ECPointToByteString(instance.pk2)  
                    + ECPointToByteString(instance.pk3) + ECPointToByteString(instance.X1)   
                    + ECPointToByteString(instance.X2)  + ECPointToByteString(instance.X3)
                    + ECPointToByteString(instance.Y); 

    // update the transcript
    transcript_str += ECPointToByteString(proof.A1) + ECPointToByteString(proof.A2) 
                    + ECPointToByteString(proof.A3) + ECPointToByteString(proof.B);  
    
    // compute the challenge
    BigInt e = HashToBigInt(transcript_str); // apply FS-transform to generate the challenge

    bool V1, V2, V3, V4; 
    ECPoint LEFT, RIGHT; 

    // check condition 1
    LEFT = instance.pk1 * proof.z; // pk1^{z}
    RIGHT = proof.A1 + instance.X1 * e;  

    V1 = (LEFT == RIGHT); //check pk1^z = A1 X1^e

    // check condition 2
    LEFT = instance.pk2 * proof.z; // pk2^{z}
    RIGHT = proof.A2 + instance.X2 * e; 

    V2 = (LEFT == RIGHT); //check pk2^z = A2 X2^e

    // check condition 3
    LEFT = instance.pk3 * proof.z; // pk3^{z}
    RIGHT = proof.A3 + instance.X3 * e; 

    V3 = (LEFT == RIGHT); //check pk3^z = A3 X3^e

    // check condition 4
    std::vector<ECPoint> vec_A{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{proof.z, proof.t}; 
    LEFT = ECPointVector_Mul(vec_A, vec_x); // g^z h^t
    RIGHT = proof.B + instance.Y * e; // B Y^e
    
    V4 = (LEFT == RIGHT); // check g^z h^t = B Y^e

    bool Validity = V1 && V2 && V3 && V4;
    #ifdef DEBUG
    std::cout << std::boolalpha << "Condition 1 (Plaintext Equality proof) = " << V1 << std::endl; 
    std::cout << std::boolalpha << "Condition 2 (Plaintext Equality proof) = " << V2 << std::endl; 
    std::cout << std::boolalpha << "Condition 3 (Plaintext Equality proof) = " << V3 << std::endl; 
    std::cout << std::boolalpha << "Condition 4 (Plaintext Equality proof) = " << V4 << std::endl; 

    if (Validity){ 
        std::cout<< "NIZK proof for triple twisted ElGamal plaintexts equality accepts >>>" << std::endl; 
    } else {
        std::cout<< "NIZK proof for triple twisted ElGamal plaintexts equality rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}

#endif



