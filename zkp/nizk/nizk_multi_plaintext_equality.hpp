/***********************************************************************************
this hpp implements NIZKPoK for Multi Plaintext Equality
***********************************************************************************/
#ifndef KUNLUN_NIZK_MPTEQ_HPP_
#define KUNLUN_NIZK_MPTEQ_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/exponential_elgamal.hpp"

namespace MultiPlaintextEquality{
    

using Serialization::operator<<; 
using Serialization::operator>>; 


struct PP
{
    ECPoint g; 
    size_t num_cipher;
    ECPoint pka;
};

// structure of instance (pk_1,...,pk_n, cipher_1,...,cipher_n, supervise_cipher_1,...,supervise_cipher_n)
struct Instance
{
   std::vector<ECPoint> vec_pk;
   std::vector<ExponentialElGamal::CT> vec_cipher_transfer;  
   std::vector<ExponentialElGamal::CT> vec_cipher_supervision; 
};

// structure of witness 
struct Witness
{
    BigInt r; // the randomness used in ElGamal encryption cipher_transfer, it will be reuse so that do not need vector<BitgInt> r
    std::vector<BigInt> vec_cipher_supervision_r; // the randomness used in ElGamal encryption cipher_supervision
    std::vector<BigInt> vec_cipher_v; // the encrypted value in ElGamal encryption cipher_transfer, it is the same as cipher_supervision
};


// structure of proof 
struct Proof
{
    std::vector<ECPoint> vec_A; // P's first round message
    std::vector<ECPoint> vec_B1; // P's first round message
    std::vector<ECPoint> vec_B2; // P's first round message
    std::vector<BigInt> vec_z1; // P's response in Zq
    std::vector<BigInt> vec_z2; // P's response in Zq
    std::vector<BigInt> vec_t; // P's response in Zq
    
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.vec_A << proof.vec_B1 << proof.vec_B2 << proof.vec_z1 << proof.vec_z2 << proof.vec_t; 
    return fout;
} 

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.vec_A >> proof.vec_B1 >> proof.vec_B2 >> proof.vec_z1 >> proof.vec_z2 >> proof.vec_t; 
    return fin;
} 


void PrintInstance(Instance &instance)
{
    std::cout << "Multi Plaintext Equality Instance >>> " << std::endl; 
    std::string note; 
    for(auto i = 0; i < instance.vec_pk.size(); i++){
        note = "instance.pk" + std::to_string(i);
        instance.vec_pk[i].Print(note); 
    }
    for(auto i = 0; i < instance.vec_cipher_transfer.size(); i++){
        note = "instance.vec_cipher_transfer" + std::to_string(i);
        instance.vec_cipher_transfer[i].X.Print(note); 
    }
    for(auto i = 0; i < instance.vec_cipher_transfer.size(); i++){
        note = "instance.vec_cipher_transfer" + std::to_string(i);
        instance.vec_cipher_transfer[i].Y.Print(note); 
    }
    for(auto i = 0; i < instance.vec_cipher_supervision.size(); i++){
        note = "instance.vec_cipher_supervision.X" + std::to_string(i);
        instance.vec_cipher_supervision[i].X.Print(note); 
    }
    for(auto i = 0; i < instance.vec_cipher_supervision.size(); i++){
        note = "instance.vec_cipher_supervision.Y" + std::to_string(i);
        instance.vec_cipher_supervision[i].Y.Print(note); 
    }
} 

void PrintWitness(Witness &witness)
{
    std::cout << "Multi Plaintext Equality Witness >>> " << std::endl; 
    witness.r.Print("witness.r"); 
    for(auto i = 0; i < witness.vec_cipher_v.size(); i++){
        std::string note = "witness.vec_cipher_v" + std::to_string(i);
        witness.vec_cipher_v[i].Print(note); 
    }
    for(auto i = 0; i < witness.vec_cipher_supervision_r.size(); i++){
        std::string note = "witness.vec_cipher_supervision_r" + std::to_string(i);
        witness.vec_cipher_supervision_r[i].Print(note); 
    }
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for Multi Plaintext Equality >>> " << std::endl; 

    std::string note;
    for(auto i = 0; i < proof.vec_A.size(); i++)
    {
        note = "proof.vec_A" + std::to_string(i);
        proof.vec_A[i].Print(note); 
    }
    for(auto i = 0; i < proof.vec_B1.size(); i++)
    {
        note = "proof.vec_B1" + std::to_string(i);
        proof.vec_B1[i].Print(note); 
    }
    for(auto i = 0; i < proof.vec_B2.size(); i++)
    {
        note = "proof.vec_B2" + std::to_string(i);
        proof.vec_B2[i].Print(note); 
    }
    for(auto i = 0; i < proof.vec_z1.size(); i++)
    {
        note = "proof.vec_z1" + std::to_string(i);
        proof.vec_z1[i].Print(note); 
    }
    for(auto i = 0; i < proof.vec_z2.size(); i++)
    {
        note = "proof.vec_z2" + std::to_string(i);
        proof.vec_z2[i].Print(note); 
    }
    for(auto i = 0; i < proof.vec_t.size(); i++)
    {
        note = "proof.vec_t" + std::to_string(i);
        proof.vec_t[i].Print(note); 
    }
} 

std::string ProofToByteString(Proof &proof)
{
    std::string str;
    for(auto i = 0; i < proof.vec_A.size(); i++)
    {
        str += proof.vec_A[i].ToByteString();
        str += proof.vec_B1[i].ToByteString();
        str += proof.vec_B2[i].ToByteString();
        str += proof.vec_z1[i].ToByteString();
        str += proof.vec_z2[i].ToByteString();
        str += proof.vec_t[i].ToByteString();
    }
    return str; 
} 


/* Setup algorithm */ 
PP Setup(ExponentialElGamal::PP pp_enc,size_t num_cipher,ECPoint pka)
{ 
    PP pp;
    pp.g = pp_enc.g;
    pp.num_cipher = num_cipher;
    pp.pka = pka;
    return pp;
}

// generate NIZK proof for cipher_transfer anf cipher_supervision encrypt the same value
Proof Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str)
{    
    Proof proof; 
   
    size_t num = pp.num_cipher; // num = N, the number of cipher

    // initialize the transcript with instance
    transcript_str = "";
    for(auto i = 0; i < num; i++)
    {
        transcript_str += instance.vec_pk[i].ToByteString();
    }
    for(auto i = 0; i < num; i++)
    {
        transcript_str += instance.vec_cipher_transfer[i].X.ToByteString();
        transcript_str += instance.vec_cipher_transfer[i].Y.ToByteString();
    }
    for(auto i = 0; i < num; i++)
    {
        transcript_str += instance.vec_cipher_supervision[i].X.ToByteString();
        transcript_str += instance.vec_cipher_supervision[i].Y.ToByteString();
    }
    // the initial random message choosed by prover
    std::vector<BigInt> vec_a(num);
    std::vector<BigInt> vec_b(num);

    proof.vec_A.resize(num);
    proof.vec_B1.resize(num);
    proof.vec_B2.resize(num);
    for(auto i = 0; i < num; i++)
    {
        vec_a[i] = GenRandomBigIntLessThan(order);
        proof.vec_A[i] = pp.g * vec_a[i]; // A = g^a
        vec_b[i] = GenRandomBigIntLessThan(order);
        proof.vec_B1[i] = pp.g* vec_b[i] + instance.vec_pk[i] * vec_a[i]; // B1 = g^b pk^a
        proof.vec_B2[i] = pp.g* vec_b[i] + pp.pka * vec_a[i]; // B2 = g^b {pk_a}^a
        transcript_str += proof.vec_A[i].ToByteString();
        transcript_str += proof.vec_B1[i].ToByteString();
        transcript_str += proof.vec_B2[i].ToByteString();
    }
    BigInt e = Hash::StringToBigInt(transcript_str);

    std::vector<BigInt> vec_z1(num);
    std::vector<BigInt> vec_z2(num);
    std::vector<BigInt> vec_t(num);

    for(auto i=0;i<num;i++){
        vec_z1[i] = (vec_a[i] + (e * witness.r) % order) % order; // z1 = a + e * r1 mod q, r1 = r
        vec_z2[i] = (vec_a[i] + (e * witness.vec_cipher_supervision_r[i]) % order) % order; // z2 = a + e * r2 mod q, r2 = vec_cipher_supervision_r
        vec_t[i] = (vec_b[i] + (e * witness.vec_cipher_v[i]) % order) % order; // t = b + e * v mod q
    }
    proof.vec_z1 = vec_z1;
    proof.vec_z2 = vec_z2;
    proof.vec_t = vec_t;

    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof; 
}


// check NIZK proof PI for cipher_transfer anf cipher_supervision encrypt the same value
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    // initialize the transcript with instance
    size_t num = pp.num_cipher;
    transcript_str = "";
    for(auto i = 0; i < num; i++){
        transcript_str += instance.vec_pk[i].ToByteString();
    }
    for(auto i = 0; i < num; i++){
        transcript_str += instance.vec_cipher_transfer[i].X.ToByteString();
        transcript_str += instance.vec_cipher_transfer[i].Y.ToByteString();
    }
    for(auto i = 0; i < num; i++){
        transcript_str += instance.vec_cipher_supervision[i].X.ToByteString();
        transcript_str += instance.vec_cipher_supervision[i].Y.ToByteString();
    }
  

    for(auto i = 0; i < num; i++){
        transcript_str += proof.vec_A[i].ToByteString();
        transcript_str += proof.vec_B1[i].ToByteString(); 
        transcript_str += proof.vec_B2[i].ToByteString();     
    }
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge
    
    std::vector<bool> vec_condition(4*num);

    ECPoint LEFT1, RIGHT1; 
    ECPoint LEFT2, RIGHT2;
    ECPoint LEFT3, RIGHT3;
    ECPoint LEFT4, RIGHT4;

    for(auto i = 0; i < num; i++)
    {
        LEFT1 = pp.g * proof.vec_z1[i]; // g^{z_1}
        RIGHT1 = proof.vec_A[i] + instance.vec_cipher_transfer[i].X * e; // A {X_1}^e
        LEFT2 = pp.g * proof.vec_z2[i]; // g^{z_2}
        RIGHT2 = proof.vec_A[i] + instance.vec_cipher_supervision[i].X * e; // A {X_2}^e
        LEFT3 = pp.g * proof.vec_t[i] + instance.vec_pk[i] * proof.vec_z1[i]; // g^{t}{pk_1}^{z_1}
        RIGHT3 = proof.vec_B1[i] + instance.vec_cipher_transfer[i].Y * e; // B_1 {Y_1}^e
        LEFT4 = pp.g * proof.vec_t[i] + pp.pka*proof.vec_z2[i]; // g^{t} {pk_a}^{z_2}
        RIGHT4 = proof.vec_B2[i] + instance.vec_cipher_supervision[i].Y * e; // B_2 {Y_2}^e  
        vec_condition[i] = (LEFT1 == RIGHT1); // check g^{z1} = A {X_1}^e
        vec_condition[num + i]= (LEFT2 == RIGHT2); // check g^{z_2} = A {X_2}^e
        vec_condition[2*num + i] = (LEFT3 == RIGHT3); // check g^{t}{pk_1}^{z_1} = B_1 {Y_1}^e
        vec_condition[3*num + i] = (LEFT4 == RIGHT4); // check g^{t} {pk_a}^{z_2} = B_2 {Y_2}^e 
    }

    bool Validity = true; 
    for(auto i = 0; i <num ; i++)
    {
        if(vec_condition[i] == false) Validity = false;
        if(vec_condition[num + i] == false) Validity = false;
        if(vec_condition[2*num + i] == false) Validity = false;
        if(vec_condition[3*num + i] == false) Validity = false;
    }

    #ifdef DEBUG
    for(auto i = 0; i <num; i++){
        std::cout << std::boolalpha << "Condition "<< std::to_string(i) <<" (Multi Plaintext Equality proof) = " 
                  << vec_condition[i] << std::endl; 
    }

    if (Validity){ 
        std::cout << "NIZK proof for " << std::to_string(num) 
                  << "-participants Multi Plaintext Equality accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZK proof for " << std::to_string(num) 
                  << "-participants Multi Plaintext Equality rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}


}

#endif



