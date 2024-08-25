/****************************************************************************
this hpp implements NIZKPoK for ElGamal ciphertext value
*****************************************************************************/
#ifndef KUNLUN_NIZK_PTBEQ_HPP_
#define KUNLUN_NIZK_PTBEQ_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/exponential_elgamal.hpp"
#include "../../zkp/nizk/nizk_many_out_of_many.hpp"

namespace PlaintextBitEquality{


using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    ECPoint g; 
    size_t num_cipher;
    size_t log_num_cipher;
    ECPoint pka;
};

// structure of instance 
struct Instance
{   
    std::vector<ExponentialElGamal::CT> vec_cipher_transfer;
    std::vector<ECPoint> vec_pk;
    ExponentialElGamal::CT value_cipher_supervison; // value_cipher_supervison C = enc(pka,v,r); the v is the transaction value
    std::vector<ExponentialElGamal::CT> vec_cipher_supervision_index_bit_sender; 
    std::vector<ExponentialElGamal::CT> vec_cipher_supervision_index_bit_receiver;
};

// structure of witness 
struct Witness
{
    BigInt v; 
    BigInt cipher_supervison_value_r;
    std::vector<BigInt> vec_cipher_supervision_index_bit_sender_v;
    std::vector<BigInt> vec_cipher_supervision_index_bit_receiver_v;
    std::vector<BigInt> vec_cipher_supervision_index_bit_sender_r;
    std::vector<BigInt> vec_cipher_supervision_index_bit_receiver_r;

};

// structure of proof 
struct Proof
{
    ECPoint A, B; // P's first round message
    BigInt z, t;  // P's response in Zq
    std::vector<ECPoint> vec_cipher_supervision_index_bit_sender_A; // P's first round message
    std::vector<ECPoint> vec_cipher_supervision_index_bit_sender_B; 
    std::vector<ECPoint> vec_cipher_supervision_index_bit_receiver_A;
    std::vector<ECPoint> vec_cipher_supervision_index_bit_receiver_B;
    std::vector<BigInt> vec_cipher_supervision_index_bit_sender_z; // P's response in Zq
    std::vector<BigInt> vec_cipher_supervision_index_bit_receiver_z;
    std::vector<BigInt> vec_cipher_supervision_index_bit_sender_t;
    std::vector<BigInt> vec_cipher_supervision_index_bit_receiver_t;
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A << proof.B << proof.z << proof.t;
    size_t vec_size = proof.vec_cipher_supervision_index_bit_sender_A.size();
    for(auto i = 0; i < vec_size; i++)
    {
        fout    << proof.vec_cipher_supervision_index_bit_sender_A[i] 
                << proof.vec_cipher_supervision_index_bit_sender_B[i] 
                << proof.vec_cipher_supervision_index_bit_receiver_A[i] 
                << proof.vec_cipher_supervision_index_bit_receiver_B[i] 
                << proof.vec_cipher_supervision_index_bit_sender_z[i] 
                << proof.vec_cipher_supervision_index_bit_receiver_z[i] 
                << proof.vec_cipher_supervision_index_bit_sender_t[i] 
                << proof.vec_cipher_supervision_index_bit_receiver_t[i];
    }

    return fout;  
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A >> proof.B >> proof.z >> proof.t;
    size_t vec_size = proof.vec_cipher_supervision_index_bit_sender_A.size();
    for(auto i = 0; i < vec_size; i++)
    {
        fin    >> proof.vec_cipher_supervision_index_bit_sender_A[i] 
                >> proof.vec_cipher_supervision_index_bit_sender_B[i] 
                >> proof.vec_cipher_supervision_index_bit_receiver_A[i] 
                >> proof.vec_cipher_supervision_index_bit_receiver_B[i] 
                >> proof.vec_cipher_supervision_index_bit_sender_z[i] 
                >> proof.vec_cipher_supervision_index_bit_receiver_z[i] 
                >> proof.vec_cipher_supervision_index_bit_sender_t[i] 
                >> proof.vec_cipher_supervision_index_bit_receiver_t[i];
    } 
    return fin; 
}


void PrintInstance(Instance &instance)
{
    std::cout << "Plaintext Bit Equality Instance >>> " << std::endl; 
    instance.value_cipher_supervison.X.Print("instance.value_cipher_supervison.X");
    instance.value_cipher_supervison.Y.Print("instance.value_cipher_supervison.Y");
    size_t vec_size = instance.vec_cipher_transfer.size();
    for(auto i = 0; i < vec_size; i++)
    {
        instance.vec_cipher_transfer[i].X.Print("instance.vec_cipher_transfer.X");
        instance.vec_cipher_transfer[i].Y.Print("instance.vec_cipher_transfer.Y");
        instance.vec_pk[i].Print("instance.vec_pk");
    }
    vec_size = instance.vec_cipher_supervision_index_bit_sender.size();
    for(auto i = 0; i < vec_size; i++)
    {
        instance.vec_cipher_supervision_index_bit_sender[i].X.Print("instance.vec_cipher_supervision_index_bit_sender.X");
        instance.vec_cipher_supervision_index_bit_sender[i].Y.Print("instance.vec_cipher_supervision_index_bit_sender.Y");
        instance.vec_cipher_supervision_index_bit_receiver[i].X.Print("instance.vec_cipher_supervision_index_bit_receiver.X");
        instance.vec_cipher_supervision_index_bit_receiver[i].Y.Print("instance.vec_cipher_supervision_index_bit_receiver.Y");
    }

} 

void PrintWitness(Witness &witness)
{
    std::cout << "Plaintext Bit Equality Witness >>> " << std::endl; 
    witness.v.Print("witness.v"); 
    witness.cipher_supervison_value_r.Print("witness.cipher_supervison_value_r");
    size_t vec_size = witness.vec_cipher_supervision_index_bit_sender_v.size();
    for(auto i = 0; i < vec_size; i++)
    {
        witness.vec_cipher_supervision_index_bit_sender_v[i].Print("witness.vec_cipher_supervision_index_bit_sender_v");
        witness.vec_cipher_supervision_index_bit_receiver_v[i].Print("witness.vec_cipher_supervision_index_bit_receiver_v");
        witness.vec_cipher_supervision_index_bit_sender_r[i].Print("witness.vec_cipher_supervision_index_bit_sender_r");
        witness.vec_cipher_supervision_index_bit_receiver_r[i].Print("witness.vec_cipher_supervision_index_bit_receiver_r");
    }
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for Plaintext Bit Equality Knowledge >>> " << std::endl; 

    proof.A.Print("proof.A");
    proof.B.Print("proof.B");
    proof.z.Print("proof.z");
    proof.t.Print("proof.t");

    size_t vec_size = proof.vec_cipher_supervision_index_bit_sender_A.size();
    for(auto i = 0; i < vec_size; i++)
    {
        PrintSplitLine('-'); 
        std::cout << "Index: " << std::to_string(i) << std::endl;
        proof.vec_cipher_supervision_index_bit_sender_A[i].Print("proof.vec_cipher_supervision_index_bit_sender_A");

        proof.vec_cipher_supervision_index_bit_sender_B[i].Print("proof.vec_cipher_supervision_index_bit_sender_B");
;
        proof.vec_cipher_supervision_index_bit_receiver_A[i].Print("proof.vec_cipher_supervision_index_bit_receiver_A");

        proof.vec_cipher_supervision_index_bit_receiver_B[i].Print("proof.vec_cipher_supervision_index_bit_receiver_B");

        proof.vec_cipher_supervision_index_bit_sender_z[i].Print("proof.vec_cipher_supervision_index_bit_sender_z");
       
        proof.vec_cipher_supervision_index_bit_receiver_z[i].Print("proof.vec_cipher_supervision_index_bit_receiver_z");
     
        proof.vec_cipher_supervision_index_bit_sender_t[i].Print("proof.vec_cipher_supervision_index_bit_sender_t");
      
        proof.vec_cipher_supervision_index_bit_receiver_t[i].Print("proof.vec_cipher_supervision_index_bit_receiver_t");
        PrintSplitLine('-'); 
    }

}

std::string ProofToByteString(Proof &proof)
{
    std::string str = proof.A.ToByteString() + proof.B.ToByteString()
                    + proof.z.ToByteString() + proof.t.ToByteString();
    size_t vec_size = proof.vec_cipher_supervision_index_bit_sender_A.size();
    for(size_t i = 0; i < vec_size; i++)
    {
        str += proof.vec_cipher_supervision_index_bit_sender_A[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_sender_B[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_receiver_A[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_receiver_B[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_sender_z[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_receiver_z[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_sender_t[i].ToByteString();
        str += proof.vec_cipher_supervision_index_bit_receiver_t[i].ToByteString();
    }
    return str;  
}

/*  Setup algorithm */
PP Setup(ExponentialElGamal::PP pp_enc,size_t num_cipher,ECPoint pka)
{ 
    PP pp;
    pp.g = pp_enc.g;
    pp.num_cipher = num_cipher;
    pp.log_num_cipher = size_t(log2(num_cipher-1)+1); 
    pp.pka = pka;

    return pp; 
}


// generate NIZK proof for value_cipher_supervison = Enc(pk_a, v; r) and vec_cipher_supervision_index_bit enc the sender and receiver index
Proof Prove(PP &pp, Instance &instance, Witness &witness, ManyOutOfMany::Proof &many_out_of_many_proof, std::string &transcript_str, ManyOutOfMany::ConsRandom cons_random)
{   
    Proof proof;
    // initialize the transcript with instance 
    size_t num = pp.num_cipher; 
    size_t m = pp.log_num_cipher;
 
    transcript_str="";
    
    transcript_str += many_out_of_many_proof.proof_ComA.ToByteString();
    transcript_str += many_out_of_many_proof.proof_ComB.ToByteString();

    size_t vec_size = many_out_of_many_proof.vec_lower_cipher_bal_left.size();
    for(size_t i = 0; i < vec_size; i++)
    {
        transcript_str += many_out_of_many_proof.vec_lower_cipher_bal_left[i].ToByteString();
        transcript_str += many_out_of_many_proof.vec_lower_cipher_bal_right[i].ToByteString();
        transcript_str += many_out_of_many_proof.vec_lower_cipher_value[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_cipher4D[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_pk[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_g[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_oppcipher[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_oppcipherpk[i].ToByteString();
    }

    BigInt w=Hash::StringToBigInt(transcript_str);
    BigInt a = GenRandomBigIntLessThan(order); 
    proof.A = pp.g * a; // A = g^a

   
    BigInt kb = cons_random.kb;
    proof.B = pp.g * kb+pp.pka*a; // B = g^bpka^a

    for(auto k=0;k<vec_size;k++)
    {
        transcript_str += many_out_of_many_proof.vec_proof_f0[k].ToByteString();
        transcript_str += many_out_of_many_proof.vec_proof_f1[k].ToByteString();
    }

    transcript_str += many_out_of_many_proof.proof_Za.ToByteString();
    BigInt z=Hash::StringToBigInt(transcript_str);
    BigInt z_square = z.ModSquare(order); // (z*z)%q; 
    BigInt z_cubic = (z_square*z) % order;

    //compute the challenge c
    transcript_str += many_out_of_many_proof.proof_Ay_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_AD_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab0_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab1_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ax_re_enc.ToByteString();
    
   
    BigInt c=Hash::StringToBigInt(transcript_str);
    

    // computer the challenge, we use the same challenge of the many_out_of_many proof
  
    BigInt w_exp_m = w.ModExp(m,order); // w_exp_m = w^m
    BigInt e = ((c * w_exp_m) %order) * z_square % order; // e = c * w^m * z^2
   
    // compute the response 
    proof.z = (a + e * witness.cipher_supervison_value_r) % order; // z = a + e * r mod q
    proof.t = (kb + e * witness.v) % order; // t = b + e * v mod q

    std::vector<BigInt>vec_al0 = cons_random.vec_al0;
    std::vector<BigInt>vec_al1 = cons_random.vec_al1;
    BigInt a0_random;
    BigInt a1_random;
    /*resize proof */
    proof.vec_cipher_supervision_index_bit_sender_A.resize(m);
    proof.vec_cipher_supervision_index_bit_sender_B.resize(m);
    proof.vec_cipher_supervision_index_bit_receiver_A.resize(m);
    proof.vec_cipher_supervision_index_bit_receiver_B.resize(m);
    proof.vec_cipher_supervision_index_bit_sender_z.resize(m);
    proof.vec_cipher_supervision_index_bit_sender_t.resize(m);
    proof.vec_cipher_supervision_index_bit_receiver_z.resize(m);
    proof.vec_cipher_supervision_index_bit_receiver_t.resize(m);

    std::vector<BigInt>vec_a0_random(m);
    std::vector<BigInt>vec_a1_random(m);

    // P's first round message
    for(auto i = 0; i < m; i++)
    {
        a0_random = GenRandomBigIntLessThan(order);
        a1_random = GenRandomBigIntLessThan(order);
        vec_a0_random[i] = a0_random;
        vec_a1_random[i] = a1_random;
        proof.vec_cipher_supervision_index_bit_sender_A[i] = pp.g * a0_random;
        proof.vec_cipher_supervision_index_bit_sender_B[i] = pp.g * vec_al0[i] + pp.pka * a0_random;
        proof.vec_cipher_supervision_index_bit_receiver_A[i] = pp.g * a1_random;
        proof.vec_cipher_supervision_index_bit_receiver_B[i] = pp.g*vec_al1[i] + pp.pka * a1_random;
    }
    //use the challenge w
    for(auto i = 0; i < m; i++)
    {
        proof.vec_cipher_supervision_index_bit_sender_z[i] = (vec_a0_random[i]+w * witness.vec_cipher_supervision_index_bit_sender_r[i]) % order; // z = a + w * r mod q
        proof.vec_cipher_supervision_index_bit_sender_t[i] = (vec_al0[i] + w  *witness.vec_cipher_supervision_index_bit_sender_v[i]) % order; // t = al0 + w * v mod q 
        proof.vec_cipher_supervision_index_bit_receiver_z[i] = (vec_a1_random[i] + w * witness.vec_cipher_supervision_index_bit_receiver_r[i]) % order;
        proof.vec_cipher_supervision_index_bit_receiver_t[i] = (vec_al1[i] + w * witness.vec_cipher_supervision_index_bit_receiver_v[i]) % order;
    }

    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof;
}


// check NIZKPoK
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof, ManyOutOfMany::Proof &many_out_of_many_proof)
{   
    size_t num = pp.num_cipher; 
    size_t m = pp.log_num_cipher; 
    // initialize the transcript with instance 
    transcript_str ="";
    transcript_str += many_out_of_many_proof.proof_ComA.ToByteString();
    transcript_str += many_out_of_many_proof.proof_ComB.ToByteString();

    size_t vec_size = many_out_of_many_proof.vec_lower_cipher_bal_left.size();
    for(size_t i = 0; i < vec_size; i++)
    {
        transcript_str += many_out_of_many_proof.vec_lower_cipher_bal_left[i].ToByteString();
        transcript_str += many_out_of_many_proof.vec_lower_cipher_bal_right[i].ToByteString();
        transcript_str += many_out_of_many_proof.vec_lower_cipher_value[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_cipher4D[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_pk[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_g[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_oppcipher[i].ToByteString();
        transcript_str += many_out_of_many_proof.lower_vec_oppcipherpk[i].ToByteString();
    }

    BigInt w=Hash::StringToBigInt(transcript_str);

    for(auto k = 0; k < vec_size; k++)
    {
        transcript_str += many_out_of_many_proof.vec_proof_f0[k].ToByteString();
        transcript_str += many_out_of_many_proof.vec_proof_f1[k].ToByteString();
    }

    transcript_str += many_out_of_many_proof.proof_Za.ToByteString();
    BigInt z=Hash::StringToBigInt(transcript_str);
    BigInt z_square = z.ModSquare(order); // (z*z)%q; 
    BigInt z_cubic = z_square*z % order;

    //compute the challenge c
    transcript_str += many_out_of_many_proof.proof_Ay_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_AD_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab0_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab1_re_enc.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ax_re_enc.ToByteString();

   
    BigInt c=Hash::StringToBigInt(transcript_str);

    // recover the challenge
    BigInt w_exp_m = w.ModExp(m,order); // w_exp_m = w^m
    BigInt e = ((c * w_exp_m) %order) * z_square % order; // e = c * w^m * z^2
    
    std::vector<bool> vec_condition(2); 
    ECPoint LEFT, RIGHT;

    // check condition 1
    LEFT = pp.g * proof.z ; //  LEFT  = g^z
    RIGHT = proof.A + instance.value_cipher_supervison.X * e; // RIGHT = A X^e
    
    vec_condition[0] = (LEFT == RIGHT); //check pk^z1 = A X^e
    
    // check condition 2
    std::vector<ECPoint> vec_base{pp.pka, pp.g}; 
    std::vector<BigInt> vec_x{proof.z, proof.t}; 
    LEFT = ECPointVectorMul(vec_base, vec_x); // LEFT = pk^z g^t
    RIGHT = proof.B + instance.value_cipher_supervison.Y * e; // RIGHT = B Y^e 

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

    bool Validity2;
    ECPoint SENDER_INDEX_LEFT1, SENDER_INDEX_RIGHT1;
    ECPoint SENDER_INDEX_LEFT2, SENDER_INDEX_RIGHT2;
    ECPoint RECEIVER_INDEX_LEFT1, Rid_RIGHT1;
    ECPoint RECEIVER_INDEX_LEFT2, RECEIVER_INDEX_RIGHT2;

    std::vector<bool> vec_condition_sender_index(m);
    std::vector<bool> vec_condition_receiver_index(m);
    bool sender_index_check1, sender_index_check2;
    bool receiver_index_check1, receiver_index_check2;
    for(auto i = 0;i < m; i++)
    {
       SENDER_INDEX_LEFT1 = pp.g * proof.vec_cipher_supervision_index_bit_sender_z[i]; // SENDER_INDEX_LEFT1 = g^z
       SENDER_INDEX_RIGHT1 = proof.vec_cipher_supervision_index_bit_sender_A[i] + instance.vec_cipher_supervision_index_bit_sender[i].X * w; // SENDER_INDEX_RIGHT1 = A X^w
       sender_index_check1 = (SENDER_INDEX_LEFT1 == SENDER_INDEX_RIGHT1);
       SENDER_INDEX_LEFT2 = pp.pka*proof.vec_cipher_supervision_index_bit_sender_z[i] + pp.g * proof.vec_cipher_supervision_index_bit_sender_t[i]; // SENDER_INDEX_LEFT2 = {pk_a}^z g^t
       SENDER_INDEX_RIGHT2 = proof.vec_cipher_supervision_index_bit_sender_B[i] + instance.vec_cipher_supervision_index_bit_sender[i].Y * w; // SENDER_INDEX_RIGHT1 = B Y^w
       sender_index_check2 = (SENDER_INDEX_LEFT2 == SENDER_INDEX_RIGHT2);
       vec_condition_sender_index[i] = sender_index_check1 && sender_index_check2;
    }
    for(auto i = 0; i < m; i++)
    {
       RECEIVER_INDEX_LEFT1 = pp.g*proof.vec_cipher_supervision_index_bit_receiver_z[i]; // RECEIVER_INDEX_LEFT1 = g^z
       Rid_RIGHT1 = proof.vec_cipher_supervision_index_bit_receiver_A[i] + instance.vec_cipher_supervision_index_bit_receiver[i].X * w; // RECEIVER_INDEX_RIGHT1 = A X^w
       receiver_index_check1 = (RECEIVER_INDEX_LEFT1 == Rid_RIGHT1);
       RECEIVER_INDEX_LEFT2 = pp.pka * proof.vec_cipher_supervision_index_bit_receiver_z[i] + pp.g * proof.vec_cipher_supervision_index_bit_receiver_t[i]; // RECEIVER_INDEX_LEFT2 = {pk_a}^z g^t
       RECEIVER_INDEX_RIGHT2 = proof.vec_cipher_supervision_index_bit_receiver_B[i] + instance.vec_cipher_supervision_index_bit_receiver[i].Y * w; // RECEIVER_INDEX_RIGHT1 = B Y^w
       receiver_index_check2 = (RECEIVER_INDEX_LEFT2 == RECEIVER_INDEX_RIGHT2);
       vec_condition_receiver_index[i] = receiver_index_check1 && receiver_index_check2;
    }
    Validity2=true;
    for(auto i = 0; i< m; i++){
        Validity2 = Validity2 && vec_condition_sender_index[i] && vec_condition_receiver_index[i];
    }
   
    #ifdef DEBUG
    PrintSplitLine('-'); 
    std::cout << "verify the NIZKPoK for value knowledge] >>>" << std::endl; 
    for(auto i = 0; i < vec_condition_sender_index.size(); i++){
        std::cout << std::boolalpha << "Condition " << i << " ( index Knowledge proof) = " 
                                    << vec_condition_sender_index[i] << vec_condition_receiver_index[i]<< std::endl; 
    }
    if (Validity2) { 
        std::cout << "NIZKPoK for [ index Knowledge ] accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZKPoK for [ index Knowledge ] rejects >>>" << std::endl; 
    }
    #endif
    bool Validity = Validity1 && Validity2;

    return Validity;
}



}
#endif
