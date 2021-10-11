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

#include "../pke/twisted_elgamal.hpp"        // implement Twisted ElGamal  
#include "../nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../nizk/nizk_plaintext_knowledge.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../bulletproofs/bullet_proof.hpp"    // implement Log Size Bulletproof

namespace Gadget{
struct PP{  
    size_t RANGE_LEN; // the maximum coin value is 2^RANGE_LEN 
    size_t LOG_RANGE_LEN; // this parameter will be used by Bulletproof
    size_t AGG_NUM; 
    size_t TRADEOFF_NUM; 
    size_t DEC_THREAD_NUM; // used by twisted ElGamal

    ECPoint g, h, u; // used for inside innerproduct statement
    std::vector<ECPoint> vec_g; 
    std::vector<ECPoint> vec_h; // the pp of innerproduct part     
};

struct Instance{
    ECPoint pk; 
    TwistedElGamal::CT ct;
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
    TwistedElGamal::CT refresh_ct; 
    DLOGEquality::Proof dlogeq_proof;  
    PlaintextKnowledge::Proof ptke_proof; 
    Bullet::Proof bullet_proof;     
};

void GetEncPPfromGadgetPP(PP &pp, TwistedElGamal::PP &enc_pp)
{
    enc_pp.MSG_LEN = pp.RANGE_LEN;  
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    enc_pp.TRADEOFF_NUM = pp.TRADEOFF_NUM; 
    enc_pp.DEC_THREAD_NUM = pp.DEC_THREAD_NUM; 
}

void GetBulletPPfromGadgetPP(PP &pp, Bullet::PP &bullet_pp)
{
    bullet_pp.RANGE_LEN = pp.RANGE_LEN; 
    bullet_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN; 
    bullet_pp.AGG_NUM = pp.AGG_NUM; 

    bullet_pp.g = pp.g; 
    bullet_pp.h = pp.h;  
    bullet_pp.u = pp.u; 
    bullet_pp.vec_g = pp.vec_g; 
    bullet_pp.vec_h = pp.vec_h; 
}

void GetDLOGEqualityPPfromGadgetPP(PP &pp, DLOGEquality::PP &dlogeq_pp)
{
    dlogeq_pp.ss_reserve = "dummy";  
}

void GetPlaintextKnowledgePPfromGadgetPP(PP &pp, PlaintextKnowledge::PP &ptknowledge_pp)
{
    ptknowledge_pp.g = pp.g; 
    ptknowledge_pp.h = pp.h; 
}

// /* 
//     the default range size is LARGE_LEN, the exact range size is SMALL_LEN 
//     this function get the difference
// */
// BigInt Get_Range_Size_Diff(size_t &LARGE_LEN, size_t &SMALL_LEN)
// {
//     BigInt large_range_size = BigInt(uint64_t(pow(2, LARGE_LEN))); 
//     BigInt small_range_size = BigInt(uint64_t(pow(2, SMALL_LEN))); 
//     BigInt range_size_diff = large_range_size - small_range_size;
//     return range_size_diff; 
// }

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

void Setup(PP &pp, size_t& RANGE_LEN, size_t &AGG_NUM, size_t &TRADEOFF_NUM, size_t &DEC_THREAD_NUM)
{
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = log2(RANGE_LEN);
    pp.DEC_THREAD_NUM = DEC_THREAD_NUM; 
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 
    pp.AGG_NUM = 2;

    pp.g = generator; 
    pp.h = Hash::StringToECPoint(pp.g.ToByteString()); 
    pp.u = GenRandomGenerator();

    pp.vec_g = GenRandomECPointVector(RANGE_LEN*AGG_NUM); 
    pp.vec_h = GenRandomECPointVector(RANGE_LEN*AGG_NUM);
}


void Prove(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                   Witness_type1 &witness, std::string &transcript_str, Proof_type1 &proof)
{
    if (CheckRange(LEFT_BOUND, RIGHT_BOUND, pp.RANGE_LEN)==false)
    {
        std::cerr << "the range is not valid" << std::endl;
        exit(EXIT_FAILURE);
    } 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromGadgetPP(pp, enc_pp);  

    PlaintextKnowledge::PP ptke_pp; 
    GetPlaintextKnowledgePPfromGadgetPP(pp, ptke_pp); 
    PlaintextKnowledge::Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = instance.ct.X;
    ptke_instance.Y = instance.ct.Y;

    PlaintextKnowledge::Witness ptke_witness;
    ptke_witness.v = witness.m;
    ptke_witness.r = witness.r;

    PlaintextKnowledge::Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str, proof.ptke_proof);  
    

    Bullet::PP bullet_pp; 
    GetBulletPPfromGadgetPP(pp, bullet_pp); 

    Bullet::Instance bullet_instance; 

    bullet_instance.C = {instance.ct.Y, instance.ct.Y}; 

    Bullet::Witness bullet_witness;
    bullet_witness.r = {witness.r, witness.r};
    bullet_witness.v = {witness.m, witness.m};

    AdjustBulletInstance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 
    AdjustBulletWitness(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_witness); 

    Bullet::Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
}


bool Verify(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                    std::string &transcript_str, Proof_type1 &proof)
{
    bool V1, V2; 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromGadgetPP(pp, enc_pp);  

    PlaintextKnowledge::PP ptke_pp; 
    GetPlaintextKnowledgePPfromGadgetPP(pp, ptke_pp); 
    PlaintextKnowledge::Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = instance.ct.X;
    ptke_instance.Y = instance.ct.Y;

    V1 = PlaintextKnowledge::Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof);  

    Bullet::PP bullet_pp; 
    GetBulletPPfromGadgetPP(pp, bullet_pp); 

    Bullet::Instance bullet_instance;  
    bullet_instance.C = {instance.ct.Y, instance.ct.Y}; 

    AdjustBulletInstance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance);  

    V2 = Bullet::Verify(bullet_pp, bullet_instance, transcript_str, proof.bullet_proof);

    return V1 && V2; 

}

void Prove(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                   Witness_type2 &witness, std::string &transcript_str, Proof_type2 &proof)
{
    if (CheckRange(LEFT_BOUND, RIGHT_BOUND, pp.RANGE_LEN)==false)
    {
        std::cerr << "the range is not valid" << std::endl;
        exit(EXIT_FAILURE);
    } 

    TwistedElGamal::PP enc_pp; 
    GetEncPPfromGadgetPP(pp, enc_pp);
      
    if(int2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        TwistedElGamal::Initialize(enc_pp);
    }


    BigInt r_star = GenRandomBigIntLessThan(order); 
    TwistedElGamal::ReEnc(enc_pp, instance.pk, witness.sk, instance.ct, r_star, proof.refresh_ct); 

    BigInt m; 
    TwistedElGamal::Dec(enc_pp, witness.sk, instance.ct, m); 

    DLOGEquality::PP dlogeq_pp; 
    GetDLOGEqualityPPfromGadgetPP(pp, dlogeq_pp); 
    DLOGEquality::Instance dlogeq_instance;
    dlogeq_instance.g1 = enc_pp.g; 
    dlogeq_instance.h1 = instance.pk; 
    dlogeq_instance.g2 = proof.refresh_ct.Y - instance.ct.Y;  
    dlogeq_instance.h2 = proof.refresh_ct.X - instance.ct.X;

    DLOGEquality::Witness dlogeq_witness;
    dlogeq_witness.w = witness.sk;  

    DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, proof.dlogeq_proof);  
    
    PlaintextKnowledge::PP ptke_pp; 
    GetPlaintextKnowledgePPfromGadgetPP(pp, ptke_pp); 
    PlaintextKnowledge::Instance ptke_instance; 
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = proof.refresh_ct.X; 
    ptke_instance.Y = proof.refresh_ct.Y;

    PlaintextKnowledge::Witness ptke_witness; 
    ptke_witness.v = m; 
    ptke_witness.r = r_star; 

    PlaintextKnowledge::Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str, proof.ptke_proof); 

    Bullet::PP bullet_pp; 
    GetBulletPPfromGadgetPP(pp, bullet_pp); 

    Bullet::Instance bullet_instance; 
    bullet_instance.C = {proof.refresh_ct.Y, proof.refresh_ct.Y}; 

    Bullet::Witness bullet_witness; 
    bullet_witness.r = {r_star, r_star};
    bullet_witness.v = {m, m};

    AdjustBulletInstance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 
    AdjustBulletWitness(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_witness);


    Bullet::Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
}


bool Verify(PP &pp, Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
            std::string &transcript_str, Proof_type2 &proof)
{
    bool V1, V2, V3; 

    DLOGEquality::PP dlogeq_pp; 
    GetDLOGEqualityPPfromGadgetPP(pp, dlogeq_pp); 
    DLOGEquality::Instance dlogeq_instance;
    dlogeq_instance.g1 = pp.g; 
    dlogeq_instance.h1 = instance.pk; 
    dlogeq_instance.g2 = proof.refresh_ct.Y - instance.ct.Y;  
    dlogeq_instance.h2 = proof.refresh_ct.X - instance.ct.X;

    V1 = DLOGEquality::Verify(dlogeq_pp, dlogeq_instance, transcript_str, proof.dlogeq_proof);   

    PlaintextKnowledge::PP ptke_pp; 
    GetPlaintextKnowledgePPfromGadgetPP(pp, ptke_pp); 
    PlaintextKnowledge::Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = proof.refresh_ct.X; 
    ptke_instance.Y = proof.refresh_ct.Y;

    V2 = PlaintextKnowledge::Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof); 

    Bullet::PP bullet_pp; 
    GetBulletPPfromGadgetPP(pp, bullet_pp); 

    Bullet::Instance bullet_instance; 
    bullet_instance.C = {proof.refresh_ct.Y, proof.refresh_ct.Y};

    AdjustBulletInstance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 

    V3 = Bullet::Verify(bullet_pp, bullet_instance, transcript_str, proof.bullet_proof); 

    return V1 && V2 && V3; 
}

}

#endif
