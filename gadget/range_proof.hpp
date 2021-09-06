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


struct Gadget_PP{  
    size_t RANGE_LEN; // the maximum coin value is 2^RANGE_LEN 
    size_t LOG_RANGE_LEN; // this parameter will be used by Bulletproof
    size_t AGG_NUM; 
    size_t TRADEOFF_NUM; 
    size_t THREAD_NUM; // used by twisted ElGamal

    ECPoint g, h, u; // used for inside innerproduct statement
    std::vector<ECPoint> vec_g; 
    std::vector<ECPoint> vec_h; // the pp of innerproduct part     
};

struct Gadget_Instance{
    ECPoint pk; 
    Twisted_ElGamal_CT ct;
};

struct Gadget1_Witness{
    BigInt r, m;    
};

struct Gadget1_Proof{  
    Plaintext_Knowledge_Proof ptke_proof; 
    Bullet_Proof bullet_proof;     
};

struct Gadget2_Witness{
    BigInt sk;    
};

struct Gadget2_Proof{
    Twisted_ElGamal_CT refresh_ct; 
    DLOG_Equality_Proof dlogeq_proof;  
    Plaintext_Knowledge_Proof ptke_proof; 
    Bullet_Proof bullet_proof;     
};



void Get_Enc_PP_from_Gadget_PP(Gadget_PP &pp, Twisted_ElGamal_PP &enc_pp)
{
    enc_pp.MSG_LEN = pp.RANGE_LEN;  
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
    enc_pp.TRADEOFF_NUM = pp.TRADEOFF_NUM; 
    enc_pp.THREAD_NUM = pp.THREAD_NUM; 
}

void Get_Bullet_PP_from_Gadget_PP(Gadget_PP &pp, Bullet_PP &bullet_pp)
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

void Get_DLOG_Equality_PP_from_Gadget_PP(Gadget_PP &pp, DLOG_Equality_PP &dlogeq_pp)
{
    dlogeq_pp.ss_reserve = "dummy";  
}

void Get_Plaintext_Knowledge_PP_from_Gadget_PP(Gadget_PP &pp, Plaintext_Knowledge_PP &ptknowledge_pp)
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
void Adjust_Bullet_Instance(Bullet_PP &bullet_pp, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, Bullet_Instance &bullet_instance)
{
    BigInt delta_left = LEFT_BOUND - bn_0; 
    bullet_instance.C[0] = bullet_instance.C[0] - bullet_pp.h * delta_left;

    BigInt delta_right = bn_2.Exp(bullet_pp.RANGE_LEN) - RIGHT_BOUND; 
    bullet_instance.C[1] = bullet_instance.C[1] + bullet_pp.h * delta_right;
}

/* adjust Bullet witness */
void Adjust_Bullet_Witness(Bullet_PP &bullet_pp, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, Bullet_Witness &bullet_witness)
{
    BigInt delta_left = LEFT_BOUND - bn_0; 
    bullet_witness.v[0] = bullet_witness.v[0] - delta_left;

    BigInt delta_right = bn_2.Exp(bullet_pp.RANGE_LEN) - RIGHT_BOUND;
    bullet_witness.v[1] = bullet_witness.v[1] + delta_right;
}

bool Check_Range(BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, size_t &RANGE_LEN)
{
    if (LEFT_BOUND > RIGHT_BOUND || RIGHT_BOUND > bn_2.Exp(RANGE_LEN)){
        std::cerr << "illegal range specification" << std::endl;
        return false; 
    }
    else return true;  
} 

void Gadget_Setup(Gadget_PP &pp, size_t& RANGE_LEN, size_t &AGG_NUM, size_t &TRADEOFF_NUM, size_t &THREAD_NUM)
{
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = log2(RANGE_LEN);
    pp.THREAD_NUM = THREAD_NUM; 
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 
    pp.AGG_NUM = 2;

    pp.g = generator; 
    pp.h = HashToPoint(ECPointToByteString(pp.g)); 
    pp.u = GenRandomGenerator();

    pp.vec_g.resize(RANGE_LEN*AGG_NUM); 
    pp.vec_h.resize(RANGE_LEN*AGG_NUM);  

    GenRandomECPointVector(pp.vec_g);
    GenRandomECPointVector(pp.vec_h);
}


void Gadget1_Prove(Gadget_PP &pp, Gadget_Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                   Gadget1_Witness &witness, std::string &transcript_str, Gadget1_Proof &proof)
{
    if (Check_Range(LEFT_BOUND, RIGHT_BOUND, pp.RANGE_LEN)==false)
    {
        exit(EXIT_FAILURE);
    } 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(pp, enc_pp);  

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = instance.ct.X;
    ptke_instance.Y = instance.ct.Y;

    Plaintext_Knowledge_Witness ptke_witness;
    ptke_witness.v = witness.m;
    ptke_witness.r = witness.r;

    NIZK_Plaintext_Knowledge_Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str, proof.ptke_proof);  
    

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(pp, bullet_pp); 

    Bullet_Instance bullet_instance; 

    bullet_instance.C = {instance.ct.Y, instance.ct.Y}; 

    Bullet_Witness bullet_witness;
    bullet_witness.r = {witness.r, witness.r};
    bullet_witness.v = {witness.m, witness.m};

    Adjust_Bullet_Instance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 
    Adjust_Bullet_Witness(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_witness); 

    Bullet_Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
}


bool Gadget1_Verify(Gadget_PP &pp, Gadget_Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                    std::string &transcript_str, Gadget1_Proof &proof)
{
    bool V1, V2; 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(pp, enc_pp);  

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = instance.ct.X;
    ptke_instance.Y = instance.ct.Y;

    V1 = NIZK_Plaintext_Knowledge_Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof);  

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(pp, bullet_pp); 

    Bullet_Instance bullet_instance;  
    bullet_instance.C = {instance.ct.Y, instance.ct.Y}; 

    Adjust_Bullet_Instance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance);  

    V2 = Bullet_Verify(bullet_pp, bullet_instance, transcript_str, proof.bullet_proof);

    return V1 && V2; 

}

void Gadget2_Prove(Gadget_PP &pp, Gadget_Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                   Gadget2_Witness &witness, std::string &transcript_str, Gadget2_Proof &proof)
{
    if (Check_Range(LEFT_BOUND, RIGHT_BOUND, pp.RANGE_LEN)==false)
    {
        exit(EXIT_FAILURE);
    } 

    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(pp, enc_pp);
      
    if(int2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        Twisted_ElGamal_Initialize(enc_pp);
    }


    BigInt r_star = GenRandomBigIntLessThan(order); 
    Twisted_ElGamal_ReEnc(enc_pp, instance.pk, witness.sk, instance.ct, r_star, proof.refresh_ct); 

    BigInt m; 
    Twisted_ElGamal_Parallel_Dec(enc_pp, witness.sk, instance.ct, m); 

    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_Gadget_PP(pp, dlogeq_pp); 
    DLOG_Equality_Instance dlogeq_instance;
    dlogeq_instance.g1 = enc_pp.g; 
    dlogeq_instance.h1 = instance.pk; 
    dlogeq_instance.g2 = proof.refresh_ct.Y - instance.ct.Y;  
    dlogeq_instance.h2 = proof.refresh_ct.X - instance.ct.X;

    DLOG_Equality_Witness dlogeq_witness;
    dlogeq_witness.w = witness.sk;  

    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, proof.dlogeq_proof);  
    
    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance; 
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = proof.refresh_ct.X; 
    ptke_instance.Y = proof.refresh_ct.Y;

    Plaintext_Knowledge_Witness ptke_witness; 
    ptke_witness.v = m; 
    ptke_witness.r = r_star; 

    NIZK_Plaintext_Knowledge_Prove(ptke_pp, ptke_instance, ptke_witness, transcript_str, proof.ptke_proof); 

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(pp, bullet_pp); 

    Bullet_Instance bullet_instance; 
    bullet_instance.C = {proof.refresh_ct.Y, proof.refresh_ct.Y}; 

    Bullet_Witness bullet_witness; 
    bullet_witness.r = {r_star, r_star};
    bullet_witness.v = {m, m};

    Adjust_Bullet_Instance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 
    Adjust_Bullet_Witness(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_witness); 

    // Print_ECPointVector(bullet_pp.vec_g, "vec_g"); 
    // Print_ECPointVector(bullet_pp.vec_g, "vec_g"); 

    // Print_ECPointVector(bullet_instance.C, "C"); 

    // std::cout << transcript_str << std::endl;
    // Print_BigIntVector(bullet_witness.r, "r"); 
    // Print_BigIntVector(bullet_witness.v, "v"); 


    Bullet_Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, proof.bullet_proof);
}


bool Gadget2_Verify(Gadget_PP &pp, Gadget_Instance &instance, BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                    std::string &transcript_str, Gadget2_Proof &proof)
{
    bool V1, V2, V3; 

    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_Gadget_PP(pp, dlogeq_pp); 
    DLOG_Equality_Instance dlogeq_instance;
    dlogeq_instance.g1 = pp.g; 
    dlogeq_instance.h1 = instance.pk; 
    dlogeq_instance.g2 = proof.refresh_ct.Y - instance.ct.Y;  
    dlogeq_instance.h2 = proof.refresh_ct.X - instance.ct.X;

    V1 = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, transcript_str, proof.dlogeq_proof);   

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_Gadget_PP(pp, ptke_pp); 
    Plaintext_Knowledge_Instance ptke_instance;
    ptke_instance.pk = instance.pk; 
    ptke_instance.X = proof.refresh_ct.X; 
    ptke_instance.Y = proof.refresh_ct.Y;

    V2 = NIZK_Plaintext_Knowledge_Verify(ptke_pp, ptke_instance, transcript_str, proof.ptke_proof); 

    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_Gadget_PP(pp, bullet_pp); 

    Bullet_Instance bullet_instance; 
    bullet_instance.C = {proof.refresh_ct.Y, proof.refresh_ct.Y};

    Adjust_Bullet_Instance(bullet_pp, LEFT_BOUND, RIGHT_BOUND, bullet_instance); 

    V3 = Bullet_Verify(bullet_pp, bullet_instance, transcript_str, proof.bullet_proof); 

    return V1 && V2 && V3; 
}

#endif
