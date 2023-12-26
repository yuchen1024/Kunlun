/***********************************************************************************
this hpp implements two useful gadgets for proving encrypted message lie 
in the range [LEFT_BOUND, RIGHT_BOUND) 
************************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#ifndef GADGET_RANGE_PROOF_HPP
#define GADGET_RANGE_PROOF_HPP

#include "../pke/twisted_exponential_elgamal.hpp"        // import Twisted Exponential ElGamal  
#include "../zkp/nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../zkp/nizk/nizk_plaintext_knowledge.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../zkp/nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../zkp/bulletproofs/bullet_proof.hpp"    // implement Log Size Bulletproof
#include "../crypto/hash.hpp"

namespace Gadget{

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP{     
    TwistedExponentialElGamal::PP enc_part; 
    Bullet::PP bullet_part; 

};

struct Instance{
    ECPoint pk; 
    TwistedExponentialElGamal::CT ct;
};

struct Witness_type1{
    BigInt r, m;    
};

struct Proof_type1{  
    PlaintextKnowledge::Proof ptke_proof; 
    Bullet::Proof bullet_proof;     
};


struct Witness_type2{
    BigInt sk;    
};

struct Proof_type2{
    TwistedExponentialElGamal::CT refresh_ct; 
    DLOGEquality::Proof dlogeq_proof;  
    PlaintextKnowledge::Proof ptke_proof; 
    Bullet::Proof bullet_proof;     
};


/* adjust Bullet instance 
* this is equivalent to show: 
* (1) x - delta_left in [0, 2^RANGE_LEN); 
* (2) x + delta_right in [0, 2^RANGE_LEN) 
*/
void AdjustBulletInstance(Bullet::PP &bullet_pp, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, Bullet::Instance &bullet_instance)
{
    BigInt delta_left = LEFT_BOUND - bn_0; 
    bullet_instance.C[0] = bullet_instance.C[0] - bullet_pp.h * delta_left;

    BigInt delta_right = bn_2.Exp(bullet_pp.RANGE_LEN) - RIGHT_BOUND; 
    bullet_instance.C[1] = bullet_instance.C[1] + bullet_pp.h * delta_right;
}

/* adjust Bullet witness */
void AdjustBulletWitness(Bullet::PP &bullet_pp, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, Bullet::Witness &bullet_witness)
{
    BigInt delta_left = LEFT_BOUND - bn_0; 
    bullet_witness.v[0] = bullet_witness.v[0] - delta_left;

    BigInt delta_right = bn_2.Exp(bullet_pp.RANGE_LEN) - RIGHT_BOUND;
    bullet_witness.v[1] = bullet_witness.v[1] + delta_right;
}

bool CheckRange(BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, size_t &RANGE_LEN)
{
    if (LEFT_BOUND > RIGHT_BOUND || RIGHT_BOUND > bn_2.Exp(RANGE_LEN)){
        std::cerr << "illegal range specification" << std::endl;
        return false; 
    }
    else return true;  
} 

PP Setup(TwistedExponentialElGamal::PP &pp_enc, Bullet::PP &pp_bullet)
{
    PP pp;
    pp.enc_part = pp_enc;
    pp.bullet_part = pp_bullet;
    return pp; 
}


Proof_type1 Prove(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                   Witness_type1 &witness, std::string &transcript_str)
{
    Proof_type1 proof; 
    if (CheckRange(LEFT_BOUND, RIGHT_BOUND, pp.bullet_part.RANGE_LEN)==false)
    {
        std::cerr << "the range is not valid" << std::endl;
        exit(EXIT_FAILURE);
    } 


    PlaintextKnowledge::PP ptke_pp = PlaintextKnowledge::Setup(pp.enc_part); 
    PlaintextKnowledge::Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.ct = instance.ct;

    PlaintextKnowledge::Witness ptke_witness;
    ptke_witness.v = witness.m;
    ptke_witness.r = witness.r;

    proof.ptke_proof = PlaintextKnowledge::Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str);  
    

    Bullet::Instance bullet_instance; 

    bullet_instance.C = {instance.ct.Y, instance.ct.Y}; 

    Bullet::Witness bullet_witness;
    bullet_witness.r = {witness.r, witness.r};
    bullet_witness.v = {witness.m, witness.m};

    AdjustBulletInstance(pp.bullet_part, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 
    AdjustBulletWitness(pp.bullet_part, LEFT_BOUND, RIGHT_BOUND, bullet_witness); 

    Bullet::Prove(pp.bullet_part, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);

    return proof; 
}


bool Verify(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                    std::string &transcript_str, Proof_type1 &proof)
{
    bool V1, V2; 

    PlaintextKnowledge::PP ptke_pp = PlaintextKnowledge::Setup(pp.enc_part); 
    PlaintextKnowledge::Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.ct = instance.ct;

    V1 = PlaintextKnowledge::Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof);  

    Bullet::Instance bullet_instance;  
    bullet_instance.C = {instance.ct.Y, instance.ct.Y}; 

    AdjustBulletInstance(pp.bullet_part, LEFT_BOUND, RIGHT_BOUND, bullet_instance);  

    V2 = Bullet::FastVerify(pp.bullet_part, bullet_instance, transcript_str, proof.bullet_proof);

    return V1 && V2; 

}

void Prove(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                   Witness_type2 &witness, std::string &transcript_str, Proof_type2 &proof)
{
    if (CheckRange(LEFT_BOUND, RIGHT_BOUND, pp.bullet_part.RANGE_LEN)==false)
    {
        std::cerr << "the range is not valid" << std::endl;
        exit(EXIT_FAILURE);
    } 
      
    if(encoding2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        TwistedExponentialElGamal::Initialize(pp.enc_part);
    }


    BigInt r_star = GenRandomBigIntLessThan(order); 
    proof.refresh_ct = TwistedExponentialElGamal::ReEnc(pp.enc_part, instance.pk, witness.sk, instance.ct, r_star); 

    BigInt m = TwistedExponentialElGamal::Dec(pp.enc_part, witness.sk, instance.ct); 

    DLOGEquality::PP dlogeq_pp = DLOGEquality::Setup();
    DLOGEquality::Instance dlogeq_instance;
    dlogeq_instance.g1 = pp.enc_part.g; 
    dlogeq_instance.h1 = instance.pk; 
    dlogeq_instance.g2 = proof.refresh_ct.Y - instance.ct.Y;  
    dlogeq_instance.h2 = proof.refresh_ct.X - instance.ct.X;

    DLOGEquality::Witness dlogeq_witness;
    dlogeq_witness.w = witness.sk;  

    proof.dlogeq_proof = DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str);  
    
    PlaintextKnowledge::PP ptke_pp = PlaintextKnowledge::Setup(pp.enc_part); 
    PlaintextKnowledge::Instance ptke_instance; 
    ptke_instance.pk = instance.pk; 
    ptke_instance.ct = proof.refresh_ct; 

    PlaintextKnowledge::Witness ptke_witness; 
    ptke_witness.v = m; 
    ptke_witness.r = r_star; 

    proof.ptke_proof = PlaintextKnowledge::Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str); 

    Bullet::Instance bullet_instance; 
    bullet_instance.C = {proof.refresh_ct.Y, proof.refresh_ct.Y}; 

    Bullet::Witness bullet_witness; 
    bullet_witness.r = {r_star, r_star};
    bullet_witness.v = {m, m};

    AdjustBulletInstance(pp.bullet_part, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 
    AdjustBulletWitness(pp.bullet_part, LEFT_BOUND, RIGHT_BOUND, bullet_witness);


    Bullet::Prove(pp.bullet_part, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
}


bool Verify(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
            std::string &transcript_str, Proof_type2 &proof)
{
    bool V1, V2, V3; 

    DLOGEquality::PP dlogeq_pp = DLOGEquality::Setup();
    DLOGEquality::Instance dlogeq_instance;
    dlogeq_instance.g1 = pp.enc_part.g; 
    dlogeq_instance.h1 = instance.pk; 
    dlogeq_instance.g2 = proof.refresh_ct.Y - instance.ct.Y;  
    dlogeq_instance.h2 = proof.refresh_ct.X - instance.ct.X;

    V1 = DLOGEquality::Verify(dlogeq_pp, dlogeq_instance, transcript_str, proof.dlogeq_proof);   

    PlaintextKnowledge::PP ptke_pp = PlaintextKnowledge::Setup(pp.enc_part); 
    PlaintextKnowledge::Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.ct = proof.refresh_ct; 

    V2 = PlaintextKnowledge::Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof); 


    Bullet::Instance bullet_instance; 
    bullet_instance.C = {proof.refresh_ct.Y, proof.refresh_ct.Y};

    AdjustBulletInstance(pp.bullet_part, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 

    V3 = Bullet::FastVerify(pp.bullet_part, bullet_instance, transcript_str, proof.bullet_proof); 

    return V1 && V2 && V3; 
}

}

#endif
