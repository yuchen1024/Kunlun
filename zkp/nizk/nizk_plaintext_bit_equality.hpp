/****************************************************************************
this hpp implements NIZKPoK for ElGamal ciphertext value
*****************************************************************************/
#ifndef KUNLUN_NIZK_ATKE_HPP_
#define KUNLUN_NIZK_ATKE_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/exponential_elgamal.hpp"
#include "../../zkp/nizk/nizk_many_out_of_many.hpp"

namespace SuperviseKnowledge1{


using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    ECPoint g; 
    size_t cipher_num;
    size_t log_cipher_num;
    ECPoint pka;
    //ECPoint h; 
};

// structure of instance 
struct Instance
{   
    std::vector<ExponentialElGamal::CT> vec_cipher;
    std::vector<ECPoint> vec_pk;
    ExponentialElGamal::CT Supervise_value;
    std::vector<ExponentialElGamal::CT> vec_Supervise_indexl0;
    std::vector<ExponentialElGamal::CT> vec_Supervise_indexl1;
};

// structure of witness 
struct Witness
{
    BigInt v; 
    BigInt Supervise_value_r;
    std::vector<BigInt> vec_Supervisesenderindex_v;
    std::vector<BigInt> vec_Supervisereceiverindex_v;
    std::vector<BigInt> vec_Supervisesenderindex_r;
    std::vector<BigInt> vec_Supervisereceiverindex_r;
    //this maybe unuesd
    BigInt r; 
};

// structure of proof 
struct Proof
{
    ECPoint valueA, valueB; // P's first round message
    BigInt valuez, valuet;  // P's response in Zq
    std::vector<ECPoint> vec_Supervise_senderindexA;
    std::vector<ECPoint> vec_Supervise_senderindexB;
    std::vector<ECPoint> vec_Supervise_receiverindexA;
    std::vector<ECPoint> vec_Supervise_receiverindexB;
    std::vector<BigInt> vec_Supervise_senderindexz;
    std::vector<BigInt> vec_Supervise_receiverindexz;
    std::vector<BigInt> vec_Supervise_senderindext;
    std::vector<BigInt> vec_Supervise_receiverindext;
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.valueA << proof.valueB << proof.valuez << proof.valuet;
    size_t vec_size = proof.vec_Supervise_senderindexA.size();
    for(auto i=0;i<vec_size;i++)
    {
        fout    << proof.vec_Supervise_senderindexA[i] 
                << proof.vec_Supervise_senderindexB[i] 
                << proof.vec_Supervise_receiverindexA[i] 
                << proof.vec_Supervise_receiverindexB[i] 
                << proof.vec_Supervise_senderindexz[i] 
                << proof.vec_Supervise_receiverindexz[i] 
                << proof.vec_Supervise_senderindext[i] 
                << proof.vec_Supervise_receiverindext[i];
    }

    return fout;  
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.valueA >> proof.valueB >> proof.valuez >> proof.valuet;
    size_t vec_size = proof.vec_Supervise_senderindexA.size();
    for(auto i=0;i<vec_size;i++)
    {
        fin    >> proof.vec_Supervise_senderindexA[i] 
                >> proof.vec_Supervise_senderindexB[i] 
                >> proof.vec_Supervise_receiverindexA[i] 
                >> proof.vec_Supervise_receiverindexB[i] 
                >> proof.vec_Supervise_senderindexz[i] 
                >> proof.vec_Supervise_receiverindexz[i] 
                >> proof.vec_Supervise_senderindext[i] 
                >> proof.vec_Supervise_receiverindext[i];
    } 
    return fin; 
}


void PrintInstance(Instance &instance)
{
    std::cout << "Supervise Knowledge Instance >>> " << std::endl; 
    instance.Supervise_value.X.Print("instance.Supervise_value.X");
    instance.Supervise_value.Y.Print("instance.Supervise_value.Y");
    size_t vec_size = instance.vec_cipher.size();
    for(auto i=0;i<vec_size;i++)
    {
        instance.vec_cipher[i].X.Print("instance.vec_cipher.X");
        instance.vec_cipher[i].Y.Print("instance.vec_cipher.Y");
        instance.vec_pk[i].Print("instance.vec_pk");
    }
    vec_size = instance.vec_Supervise_indexl0.size();
    for(auto i=0;i<vec_size;i++)
    {
        instance.vec_Supervise_indexl0[i].X.Print("instance.vec_Supervise_indexl0.X");
        instance.vec_Supervise_indexl0[i].Y.Print("instance.vec_Supervise_indexl0.Y");
        instance.vec_Supervise_indexl1[i].X.Print("instance.vec_Supervise_indexl1.X");
        instance.vec_Supervise_indexl1[i].Y.Print("instance.vec_Supervise_indexl1.Y");
    }

} 

void PrintWitness(Witness &witness)
{
    std::cout << "Supervise1 Knowledge Witness >>> " << std::endl; 
    witness.v.Print("witness.v"); 
    witness.r.Print("witness.r"); 
    witness.Supervise_value_r.Print("witness.Supervise_value_r");
    size_t vec_size = witness.vec_Supervisesenderindex_v.size();
    for(auto i=0;i<vec_size;i++)
    {
        witness.vec_Supervisesenderindex_v[i].Print("witness.vec_Supervisesenderindex_v");
        witness.vec_Supervisereceiverindex_v[i].Print("witness.vec_Supervisereceiverindex_v");
        witness.vec_Supervisesenderindex_r[i].Print("witness.vec_Supervisesenderindex_r");
        witness.vec_Supervisereceiverindex_r[i].Print("witness.vec_Supervisereceiverindex_r");
    }
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for Supervise1 Knowledge >>> " << std::endl; 

    proof.valueA.Print("proof.valueA");
    proof.valueB.Print("proof.valueB");
    proof.valuez.Print("proof.valuez");
    proof.valuet.Print("proof.valuet");
    size_t vec_size = proof.vec_Supervise_senderindexA.size();
    for(auto i=0;i<vec_size;i++)
    {
        std::cout<<"senderindexA"<<i<<std::endl;
        proof.vec_Supervise_senderindexA[i].Print("proof.vec_Supervise_senderindexA");
        std::cout<<"senderindexB"<<i<<std::endl;
        proof.vec_Supervise_senderindexB[i].Print("proof.vec_Supervise_senderindexB");
        std::cout<<"receiverindexA"<<i<<std::endl;
        proof.vec_Supervise_receiverindexA[i].Print("proof.vec_Supervise_receiverindexA");
        std::cout<<"receiverindexB"<<i<<std::endl;
        proof.vec_Supervise_receiverindexB[i].Print("proof.vec_Supervise_receiverindexB");
        std::cout<<"senderindexz"<<i<<std::endl;
        proof.vec_Supervise_senderindexz[i].Print("proof.vec_Supervise_senderindexz");
        std::cout<<"receiverindexz"<<i<<std::endl;
        proof.vec_Supervise_receiverindexz[i].Print("proof.vec_Supervise_receiverindexz");
        std::cout<<"senderindext"<<i<<std::endl;
        proof.vec_Supervise_senderindext[i].Print("proof.vec_Supervise_senderindext");
        std::cout<<"receiverindext"<<i<<std::endl;
        proof.vec_Supervise_receiverindext[i].Print("proof.vec_Supervise_receiverindext");
    }

}

std::string ProofToByteString(Proof &proof)
{
    std::string str = proof.valueA.ToByteString() + proof.valueB.ToByteString()
     + proof.valuez.ToByteString() + proof.valuet.ToByteString();
    size_t vec_size = proof.vec_Supervise_senderindexA.size();
    for(size_t i=0;i<vec_size;i++)
    {
        str+=proof.vec_Supervise_senderindexA[i].ToByteString();
        str+=proof.vec_Supervise_senderindexB[i].ToByteString();
        str+=proof.vec_Supervise_receiverindexA[i].ToByteString();
        str+=proof.vec_Supervise_receiverindexB[i].ToByteString();
        str+=proof.vec_Supervise_senderindexz[i].ToByteString();
        str+=proof.vec_Supervise_receiverindexz[i].ToByteString();
        str+=proof.vec_Supervise_senderindext[i].ToByteString();
        str+=proof.vec_Supervise_receiverindext[i].ToByteString();
    }
    return str;  
}

/*  Setup algorithm */
PP Setup(ExponentialElGamal::PP pp_enc,size_t cipher_num,ECPoint pka)
{ 
    PP pp;
    pp.g = pp_enc.g;
    pp.cipher_num = cipher_num;
    pp.log_cipher_num =size_t(log2(cipher_num-1)+1); 
    pp.pka = pka;

    #ifdef DEBUG
        std::cout << "generate public parameters of NIZK for plaintext knowledge >>>" << std::endl; 
        pp.g.Print("pp.g"); 
        pp.h.Print("pp.h"); 
    #endif

    return pp; 
}


// generate NIZK proof for Supervise_value = Enc(pk_a, v; r) and vec_Supervise_index enc the sender and receiver index
Proof Prove(PP &pp, Instance &instance, Witness &witness,ManyOutOfMany::Proof &mom_proof,std::string &transcript_str,ManyOutOfMany::ConsRandom cons_random)
{   
    Proof proof;
    // initialize the transcript with instance 
    size_t num = pp.cipher_num; 
    size_t m = pp.log_cipher_num;
 
    transcript_str="";
    
    transcript_str+=mom_proof.proof_ComA.ToByteString();
    transcript_str+=mom_proof.proof_ComB.ToByteString();

    size_t vec_size = mom_proof.vec_lower_cipher_bal_left.size();
    for(size_t i=0;i<vec_size;i++)
    {
        transcript_str+=mom_proof.vec_lower_cipher_bal_left[i].ToByteString();
        transcript_str+=mom_proof.vec_lower_cipher_bal_right[i].ToByteString();
        transcript_str+=mom_proof.vec_lower_cipher_value[i].ToByteString();
        transcript_str+=mom_proof.lower_cipher4D[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_pk[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_g[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_oppcipher[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_oppcipherpk[i].ToByteString();
    }

    BigInt w=Hash::StringToBigInt(transcript_str);
    BigInt a = GenRandomBigIntLessThan(order); 
    proof.valueA = pp.g * a; // A = g^a

   
    BigInt kb = cons_random.kb;
    proof.valueB = pp.g * kb+pp.pka*a; // B = g^bpka^a

    for(auto k=0;k<vec_size;k++)
    {
        transcript_str += mom_proof.vec_proof_f0[k].ToByteString();
        transcript_str += mom_proof.vec_proof_f1[k].ToByteString();
    }

    transcript_str += mom_proof.proof_Za.ToByteString();
    BigInt z=Hash::StringToBigInt(transcript_str);
    BigInt zsquare= z*z%order; 
    BigInt zcube= zsquare*z%order;
    //compute the challenge c
    transcript_str+=mom_proof.proof_Ay_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_AD_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_Ab0_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_Ab1_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_Ax_re_enc.ToByteString();
    
   
    BigInt c=Hash::StringToBigInt(transcript_str);
    

    // computer the challenge,we use the same challenge of the right proof
    //BigInt e = Hash::StringToBigInt(transcript_str); // V's challenge in Zq: apply FS-transform to generate the challenge
    BigInt wem=w.ModExp(m,order);
    BigInt e = (c*wem%order)*zsquare%order;
   
    // compute the response 
    proof.valuez = (a + e * witness.Supervise_value_r) % order; // z = a+e*r mod q
    proof.valuet = (kb + e * witness.v) % order; // t = b+e*v mod q

    std::vector<BigInt>vec_al0=cons_random.vec_al0;
    std::vector<BigInt>vec_al1=cons_random.vec_al1;
    BigInt a0_random;
    BigInt a1_random;
    /*resize proof */
    proof.vec_Supervise_senderindexA.resize(m);
    proof.vec_Supervise_senderindexB.resize(m);
    proof.vec_Supervise_receiverindexA.resize(m);
    proof.vec_Supervise_receiverindexB.resize(m);
    proof.vec_Supervise_senderindexz.resize(m);
    proof.vec_Supervise_senderindext.resize(m);
    proof.vec_Supervise_receiverindexz.resize(m);
    proof.vec_Supervise_receiverindext.resize(m);

    std::vector<BigInt>vec_a0_random(m);
    std::vector<BigInt>vec_a1_random(m);

    for(auto i=0;i<m;i++){
        a0_random=GenRandomBigIntLessThan(order);
        a1_random=GenRandomBigIntLessThan(order);
        vec_a0_random[i]=a0_random;
        vec_a1_random[i]=a1_random;
        proof.vec_Supervise_senderindexA[i]=pp.g*a0_random;
        proof.vec_Supervise_senderindexB[i]=pp.g*vec_al0[i]+pp.pka*a0_random;
        proof.vec_Supervise_receiverindexA[i]=pp.g*a1_random;
        proof.vec_Supervise_receiverindexB[i]=pp.g*vec_al1[i]+pp.pka*a1_random;
    }
    //use the challenge w
    for(auto i=0;i<m;i++){
        proof.vec_Supervise_senderindexz[i]=(vec_a0_random[i]+w*witness.vec_Supervisesenderindex_r[i])%order;
        proof.vec_Supervise_senderindext[i]=(vec_al0[i]+w*witness.vec_Supervisesenderindex_v[i])%order;
        proof.vec_Supervise_receiverindexz[i]=(vec_a1_random[i]+w*witness.vec_Supervisereceiverindex_r[i])%order;
        proof.vec_Supervise_receiverindext[i]=(vec_al1[i]+w*witness.vec_Supervisereceiverindex_v[i])%order;
    }

    //additional check
    for(auto i=0;i<m;i++){
        if(proof.vec_Supervise_senderindext[i]==mom_proof.vec_proof_f0[i])
        {
            //std::cout<<"senderindex challenge reuse right"<<std::endl;
        }
        else{
            std::cout<<"senderindex challenge reuse wrong"<<std::endl;
        }
        if(proof.vec_Supervise_receiverindext[i]==mom_proof.vec_proof_f1[i])
        {
            //std::cout<<"receiver challenge reuse right"<<std::endl;
        }
        else{
            std::cout<<"receiver challenge reuse wrong"<<std::endl;
        }
    }
    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof;
}


// check NIZKPoK
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof,ManyOutOfMany::Proof &mom_proof)
{   
    size_t num = pp.cipher_num; 
    size_t m = pp.log_cipher_num; 
    // initialize the transcript with instance 
    transcript_str ="";
    transcript_str+=mom_proof.proof_ComA.ToByteString();
    transcript_str+=mom_proof.proof_ComB.ToByteString();

    size_t vec_size = mom_proof.vec_lower_cipher_bal_left.size();
    for(size_t i=0;i<vec_size;i++)
    {
        transcript_str+=mom_proof.vec_lower_cipher_bal_left[i].ToByteString();
        transcript_str+=mom_proof.vec_lower_cipher_bal_right[i].ToByteString();
        transcript_str+=mom_proof.vec_lower_cipher_value[i].ToByteString();
        transcript_str+=mom_proof.lower_cipher4D[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_pk[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_g[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_oppcipher[i].ToByteString();
        transcript_str+=mom_proof.lower_vec_oppcipherpk[i].ToByteString();
    }

    BigInt w=Hash::StringToBigInt(transcript_str);

    for(auto k=0;k<vec_size;k++)
    {
        transcript_str += mom_proof.vec_proof_f0[k].ToByteString();
        transcript_str += mom_proof.vec_proof_f1[k].ToByteString();
    }

    transcript_str += mom_proof.proof_Za.ToByteString();
    BigInt z=Hash::StringToBigInt(transcript_str);
    BigInt zsquare= z*z%order; 
    BigInt zcube= zsquare*z%order;
    //compute the challenge c
    transcript_str+=mom_proof.proof_Ay_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_AD_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_Ab0_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_Ab1_re_enc.ToByteString();
    transcript_str+=mom_proof.proof_Ax_re_enc.ToByteString();

   
    BigInt c=Hash::StringToBigInt(transcript_str);
    // recover the challenge
    BigInt wem=w.ModExp(m,order);
    BigInt e = (c*wem%order)*zsquare%order;

    
    std::vector<bool> vec_condition(2); 
    ECPoint LEFT, RIGHT;

    // check condition 1
    LEFT = pp.g * proof.valuez ; //  LEFT  = g^z
    RIGHT = proof.valueA + instance.Supervise_value.X*e; // RIGHT = A X^e
    
    vec_condition[0] = (LEFT == RIGHT); //check pk^z1 = A X^e
    
    // check condition 2
    std::vector<ECPoint> vec_base{pp.pka, pp.g}; 
    std::vector<BigInt> vec_x{proof.valuez, proof.valuet}; 
    LEFT = ECPointVectorMul(vec_base, vec_x); // LEFT = pk^z g^t
    RIGHT = proof.valueB + instance.Supervise_value.Y * e; // RIGHT = B Y^e 

    vec_condition[1] = (LEFT == RIGHT); //check g^z1 h^z2 = B Y^e

    bool Validity1 = vec_condition[0] && vec_condition[1];

    #ifdef DEBUG
    PrintSplitLine('-'); 
    std::cout << "verify the NIZKPoK for value knowledge] >>>" << std::endl; 
    for(auto i = 0; i < vec_condition.size(); i++){
        std::cout << std::boolalpha << "Condition " << i << " (value Knowledge proof) = " 
                                    << vec_condition[i] << std::endl; 
    }
    if (Validity1) { 
        std::cout << "NIZKPoK for [value Knowledge ] accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZKPoK for [value Knowledge ] rejects >>>" << std::endl; 
    }
    #endif

    bool Validity2 ;
    ECPoint Sid_LEFT1, Sid_RIGHT1;
    ECPoint Sid_LEFT2, Sid_RIGHT2;
    ECPoint Rid_LEFT1, Rid_RIGHT1;
    ECPoint Rid_LEFT2, Rid_RIGHT2;

    std::vector<bool> vec_conditionsid(m);
    std::vector<bool> vec_conditionrid(m);
    bool sidcheck1,sidcheck2;
    bool ridcheck1,ridcheck2;
    for(auto i=0;i<m;i++){
       Sid_LEFT1=pp.g*proof.vec_Supervise_senderindexz[i];
       Sid_RIGHT1=proof.vec_Supervise_senderindexA[i]+instance.vec_Supervise_indexl0[i].X*w;
       sidcheck1=(Sid_LEFT1==Sid_RIGHT1);
       Sid_LEFT2=pp.pka*proof.vec_Supervise_senderindexz[i]+pp.g*proof.vec_Supervise_senderindext[i];
       Sid_RIGHT2=proof.vec_Supervise_senderindexB[i]+instance.vec_Supervise_indexl0[i].Y*w;
       sidcheck2=(Sid_LEFT2==Sid_RIGHT2);
       vec_conditionsid[i]=sidcheck1&&sidcheck2;
    }
    for(auto i=0;i<m;i++){
       Rid_LEFT1=pp.g*proof.vec_Supervise_receiverindexz[i];
       Rid_RIGHT1=proof.vec_Supervise_receiverindexA[i]+instance.vec_Supervise_indexl1[i].X*w;
       ridcheck1=(Rid_LEFT1==Rid_RIGHT1);
       Rid_LEFT2=pp.pka*proof.vec_Supervise_receiverindexz[i]+pp.g*proof.vec_Supervise_receiverindext[i];
       Rid_RIGHT2=proof.vec_Supervise_receiverindexB[i]+instance.vec_Supervise_indexl1[i].Y*w;
       ridcheck2=(Rid_LEFT2==Rid_RIGHT2);
       vec_conditionrid[i]=ridcheck1&&ridcheck2;
    }
    Validity2=true;
    for(auto i=0;i<m;i++){
        Validity2=Validity2&&vec_conditionsid[i]&&vec_conditionrid[i];
    }
   
    #ifdef DEBUG
    PrintSplitLine('-'); 
    std::cout << "verify the NIZKPoK for value knowledge] >>>" << std::endl; 
    for(auto i = 0; i < vec_conditionsid.size(); i++){
        std::cout << std::boolalpha << "Condition " << i << " ( index Knowledge proof) = " 
                                    << vec_conditionsid[i] << vec_conditionrid[i]<< std::endl; 
    }
    if (Validity2) { 
        std::cout << "NIZKPoK for [ index Knowledge ] accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZKPoK for [ index Knowledge ] rejects >>>" << std::endl; 
    }
    #endif
    bool Validity = Validity1&&Validity2;

    return Validity;
}



}
#endif
