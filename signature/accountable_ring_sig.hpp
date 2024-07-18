/***********************************************************************************
this hpp implements and improves the scheme in ESORICS 2015
Short Accountable Ring Signatures Based on DDH
by replacing Exponential ElGamal with twisted Exponential ElGamal
***********************************************************************************/
#ifndef ACCOUNTABLE_RING_SIG_HPP_
#define ACCOUNTABLE_RING_SIG_HPP_

#include "../zkp/nizk/nizk_enc_relation.hpp"
#include "../zkp/nizk/nizk_dlog_equality.hpp"

namespace AccountableRingSig{

// define structure of PT_EQ_Proof 
struct PP
{
    Pedersen::PP com_part;
    TwistedExponentialElGamal::PP enc_part; 
    ECPoint ek;  
};

struct SP
{
    BigInt dk;
};

// structure of keypair
struct KeyPair
{
    ECPoint vk;
    BigInt sk;   
};

// structure of proof 
struct Signature
{
    EncRelation::Proof correct_encryption_proof; 
    BigInt z_s, z_t;   
    TwistedExponentialElGamal::CT ct_vk, ct_s;  
};
 

/* Setup algorithm */ 
std::tuple<PP, SP> Setup(size_t N_max)
{ 
    PP pp;
    SP sp;
    pp.com_part = Pedersen::Setup(N_max);


    size_t MSG_LEN = 32; 
    size_t TRADEOFF_NUM = 7; 
    pp.enc_part = TwistedExponentialElGamal::Setup(MSG_LEN, TRADEOFF_NUM);
    
    std::tie(pp.ek, sp.dk) = TwistedExponentialElGamal::KeyGen(pp.enc_part); 
    return {pp, sp}; 
}

std::tuple<ECPoint, BigInt> KeyGen(PP &pp)
{
    BigInt sk = GenRandomBigIntLessThan(order); 
    ECPoint vk = pp.enc_part.g * sk;
    return {vk, sk};      
}  

// generate NIZK proof for Ci = Enc(pki, v; r) i={1,2,3} the witness is (r, v)
Signature Sign(PP &pp, BigInt &sk, std::vector<ECPoint> &vec_R, std::string &message)
{    
    Signature sigma; 

    ECPoint vk = pp.enc_part.g * sk; 

    size_t N = vec_R.size();
    size_t l = N;  
    for(auto i = 0; i < N; i++){
        if(vec_R[i] == vk){
           l = i; break;  
        }
    }
    if(l == N) std::cerr << "sk does not match the vk ring" << std::endl; 

    BigInt r = GenRandomBigIntLessThan(order); 
    sigma.ct_vk = TwistedExponentialElGamal::Enc(pp.enc_part, pp.ek, vk, r); 
    
    BigInt t = GenRandomBigIntLessThan(order); 
    BigInt s = GenRandomBigIntLessThan(order); 
    sigma.ct_s = TwistedExponentialElGamal::Enc(pp.enc_part, pp.ek, pp.enc_part.g * s, t); 

    
    std::vector<TwistedExponentialElGamal::CT> vec_CT(N); 
    for(auto i = 0; i < N; i++){
        vec_CT[i] = TwistedExponentialElGamal::Enc(pp.enc_part, pp.ek, vec_R[i], bn_0); 
        vec_CT[i] = TwistedExponentialElGamal::HomoSub(sigma.ct_vk, vec_CT[i]); 
    }

    size_t n = 2;
    EncRelation::PP nizk_pp = EncRelation::Setup(pp.com_part, pp.enc_part, n);

    EncRelation::Instance nizk_instance; 
    nizk_instance.ek = pp.ek;
    nizk_instance.vec_CT = vec_CT; 
    
    EncRelation::Witness nizk_witness; 
    nizk_witness.r = r; 
    nizk_witness.l = l;

    std::string transcript_str = message; 

    sigma.correct_encryption_proof = EncRelation::Prove(nizk_pp, nizk_instance, nizk_witness, transcript_str); 

    BigInt x = Hash::StringToBigInt(transcript_str);

    sigma.z_s = (sk * x + s) % order; 
    sigma.z_t = (r * x + t) % order; 

    return sigma; 
}


// check NIZK proof PI for Ci = Enc(pki, m; r) the witness is (r1, r2, m)
bool Verify(PP &pp, std::vector<ECPoint> &vec_R, std::string &message, Signature &sigma)
{
    size_t N = vec_R.size();

    std::vector<TwistedExponentialElGamal::CT> vec_CT(N); 
    for(auto i = 0; i < N; i++){
        vec_CT[i] = TwistedExponentialElGamal::Enc(pp.enc_part, pp.ek, vec_R[i], bn_0); 
        vec_CT[i] = TwistedExponentialElGamal::HomoSub(sigma.ct_vk, vec_CT[i]); 
    }

    size_t n = 2;
    EncRelation::PP nizk_pp = EncRelation::Setup(pp.com_part, pp.enc_part, n);

    EncRelation::Instance nizk_instance; 
    nizk_instance.ek = pp.ek;
    nizk_instance.vec_CT = vec_CT; 
    
    std::vector<bool> vec_condition(2, true); 

    std::string transcript_str = message;     
    vec_condition[0] = EncRelation::Verify(nizk_pp, nizk_instance, transcript_str, sigma.correct_encryption_proof); 

    BigInt x = Hash::StringToBigInt(transcript_str);

    TwistedExponentialElGamal::CT ct_left = TwistedExponentialElGamal::ScalarMul(sigma.ct_vk, x); 
    ct_left = TwistedExponentialElGamal::HomoAdd(ct_left, sigma.ct_s); 
    TwistedExponentialElGamal::CT ct_right = TwistedExponentialElGamal::Enc(pp.enc_part, pp.ek, pp.enc_part.g * sigma.z_s, sigma.z_t); 
    vec_condition[1] = (ct_left == ct_right); 

    bool Validity = vec_condition[0] && vec_condition[1]; 


    #ifdef DEBUG
    for(auto i = 0; i < 2; i++){
        std::cout << std::boolalpha << "Condition "<< std::to_string(i) <<" (accountable ring signature) = " 
                  << vec_condition[i] << std::endl; 
    }

    if (Validity){ 
        std::cout << "accountable ring signature accepts >>>" << std::endl; 
    } else {
        std::cout << "accountable ring signature rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}

std::tuple<ECPoint, DLOGEquality::Proof> Open(PP &pp, SP &sp, std::vector<ECPoint> &vec_R, Signature &sigma)
{
    DLOGEquality::Proof correct_decryption_proof;
    ECPoint vk = TwistedExponentialElGamal::DecECPoint(pp.enc_part, sp.dk, sigma.ct_vk); 
    size_t N = vec_R.size();
    size_t l = N;  
    for(auto i = 0; i < N; i++){
        if(vec_R[i] == vk){
           l = i; break;  
        }
    }
    if(l == N) std::cerr << "open fails: disclosed vk does not match the vk ring" << std::endl; 
    else{ 
        std::cout << "open succeeds: the " << l << "-vk sign the message" << std::endl; 
    }

    DLOGEquality::PP nizk_pp = DLOGEquality::Setup(); 
    
    DLOGEquality::Instance nizk_instance; 
    nizk_instance.g1 = pp.enc_part.g; 
    nizk_instance.h1 = pp.ek; 
    nizk_instance.g2 = sigma.ct_vk.Y - vk; 
    nizk_instance.h2 = sigma.ct_vk.X; 

    DLOGEquality::Witness nizk_witness; 
    nizk_witness.w = sp.dk;

    std::string transcript_str = ""; 
    correct_decryption_proof = DLOGEquality::Prove(nizk_pp, nizk_instance, nizk_witness, transcript_str); 

    return {vk, correct_decryption_proof}; 
}


bool Justify(PP &pp, std::vector<ECPoint> &vec_R, Signature &sigma, 
             ECPoint &vk, DLOGEquality::Proof &correct_decryption_proof)
{
    DLOGEquality::PP nizk_pp; 
    nizk_pp.ss_reserve = "";
    
    DLOGEquality::Instance nizk_instance; 
    nizk_instance.g1 = pp.enc_part.g; 
    nizk_instance.h1 = pp.ek; 
    nizk_instance.g2 = sigma.ct_vk.Y - vk;
    nizk_instance.h2 = sigma.ct_vk.X; 

    std::string transcript_str = "";

    bool Validity = DLOGEquality::Verify(nizk_pp, nizk_instance, transcript_str, correct_decryption_proof); 

    if(Validity == true){
        std::cout << "the opening is correct" << std::endl;
    }
    else{
        std::cout << "the opening is not correct" << std::endl;
    }
    return Validity; 
}

}
#endif



