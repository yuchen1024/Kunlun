/***********************************************************************************
this hpp implements many_out_of_many proof 
***********************************************************************************/
#ifndef MANY_OUT_OF_MANY_HPP_
#define MANY_OUT_OF_MANY_HPP_
#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../commitment/pedersen.hpp"
#include "../../utility/polymul.hpp"
#include <utility>
#include <iostream>


namespace ManyOutOfMany{
    
using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of ManyOutOfManyProof
struct PP
{
    size_t num_cipher;
    size_t log_num_cipher;
    Pedersen::PP com_part;
    ECPoint g;
   
};
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.num_cipher << pp.log_num_cipher << pp.com_part << pp.g;
    return fout;
}
std::ifstream &operator>>(std::ifstream &fin, PP& pp)
{
    fin >> pp.num_cipher >> pp.log_num_cipher >> pp.com_part >> pp.g;
    return fin;  
}

struct Instance
{
    // devide the cipher into two parts in order to compute efficient
    std::vector<ECPoint> vec_cipher_balance_left; // vec_cipher_balance_left is the left part of balance cipher
    std::vector<ECPoint> vec_cipher_balance_right; // vec_cipher_balance_right is the right part of balance cipher
    std::vector<ECPoint> vec_cipher_transfer_left; // vec_cipher_transfer_left = g^v {pk_i}^r, v is the transfered value, 
                                                   // the value of sender is -v, receiver is v, the others is 0
    ECPoint cipher_transfer_right; // cipher_transfer_right = g^r, the randomness will be reused
    std::vector<ECPoint> vec_pk; // participants's pk
    ECPoint gepoch;
    ECPoint uepoch;
};
struct Witness
{
    BigInt sender_index; // sender's index
    BigInt receiver_index; // receiver's index
    BigInt value; // sender's transfer value
    BigInt sk; //sender's sk
    BigInt r; // the randomness used in the cipher_transfer
    BigInt vprime; // vprime = sender's balance - transfer value
};

// this structure in order to achieve the randomness reuse, if combine the proof into one, then this is not need
struct ConsistencyRandom
{
    BigInt kb;
    std::vector<BigInt> vec_al0; // randomness choosed in bit commitment
    std::vector<BigInt> vec_al1;
};

// define structure of ManyOutOfManyProof
struct Proof
{
    ECPoint proof_commitment_A, proof_commitment_B ;
    std::vector<ECPoint> proof_vec_lower_cipher_balance_left; // the lower order terms of the left part of cipher_balance
    std::vector<ECPoint> proof_vec_lower_cipher_balance_right; // the lower order terms of the right part of cipher_balance
    std::vector<ECPoint> proof_vec_lower_cipher_transfer_left; //  the lower order terms of the left part of cipher_transfer
    std::vector<ECPoint> proof_lower_cipher_transfer_right; // the lower order terms of the right part of cipher_transfer
    std::vector<ECPoint> proof_vec_lower_pk; 
    std::vector<ECPoint> proof_vec_lower_g;
    std::vector<ECPoint> proof_vec_lower_opposite_cipher; // the lower order terms of the opposite_cipher
    std::vector<ECPoint> proof_vec_lower_opposite_cipher_g;
    std::vector<BigInt> proof_vec_eval_f0; // evaluations of linear polynomials F0(X) = b0 * X + a0 at the verifiers challenge x
    std::vector<BigInt> proof_vec_eval_f1; // evaluations of linear polynomials F1(X) = b1 * X + a1 at the verifiers challenge x
    BigInt proof_Za; // P's response in Zq, Za = rB * w + rA
    BigInt proof_Ssk, proof_Sr, proof_Sb0, proof_Sb1; // P's response in Zq
    ECPoint proof_Ay_re_encryption, proof_AD_re_encryption, proof_Ab0_re_encryption, proof_Ab1_re_encryption, proof_Ax_re_encryption; // P's response in \mathbb{G}
    ECPoint proof_Au; // P's response in \mathbb{G}
 
};
std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.proof_commitment_A << proof.proof_commitment_B;
    size_t m = proof.proof_vec_lower_cipher_balance_left.size();
    for(auto i = 0;i < m; i++)
    {
        fout << proof.proof_vec_lower_cipher_balance_left[i]
             << proof.proof_vec_lower_cipher_balance_right[i]
             << proof.proof_vec_lower_cipher_transfer_left[i]
             << proof.proof_lower_cipher_transfer_right[i]
             << proof.proof_vec_lower_pk[i]
             << proof.proof_vec_lower_g[i]
             << proof.proof_vec_lower_opposite_cipher[i]
             << proof.proof_vec_lower_opposite_cipher_g[i]
             << proof.proof_vec_eval_f0[i]
             << proof.proof_vec_eval_f1[i];
    }
    fout << proof.proof_Ssk << proof.proof_Sr
         << proof.proof_Sb0 << proof.proof_Sb1;
    fout << proof.proof_Ay_re_encryption << proof.proof_AD_re_encryption
         << proof.proof_Ab0_re_encryption << proof.proof_Ab1_re_encryption
         << proof.proof_Ax_re_encryption << proof.proof_Au; 

    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.proof_commitment_A >> proof.proof_commitment_B;
    size_t m = proof.proof_vec_lower_cipher_balance_left.size();
    for(auto i = 0; i < m; i++)
    {
        fin >> proof.proof_vec_lower_cipher_balance_left[i]
            >> proof.proof_vec_lower_cipher_balance_right[i]
            >> proof.proof_vec_lower_cipher_transfer_left[i]
            >> proof.proof_lower_cipher_transfer_right[i]
            >> proof.proof_vec_lower_pk[i]
            >> proof.proof_vec_lower_g[i]
            >> proof.proof_vec_lower_opposite_cipher[i]
            >> proof.proof_vec_lower_opposite_cipher_g[i]
            >> proof.proof_vec_eval_f0[i]
            >> proof.proof_vec_eval_f1[i];
    }
    fin >> proof.proof_Ssk >> proof.proof_Sr
        >> proof.proof_Sb0 >> proof.proof_Sb1;
    fin >> proof.proof_Ay_re_encryption >> proof.proof_AD_re_encryption
        >> proof.proof_Ab0_re_encryption >> proof.proof_Ab1_re_encryption
        >> proof.proof_Ax_re_encryption >> proof.proof_Au;
    return fin; 
}
void PrintProof(Proof &proof)
{
    
    proof.proof_commitment_A.Print("proof_commitment_A");
    proof.proof_commitment_B.Print("proof_commitment_B");
    size_t m = proof.proof_vec_lower_cipher_balance_left.size();
    for(auto i = 0; i < m; i++)
    {
        proof.proof_vec_lower_cipher_balance_left[i].Print("proof_vec_lower_cipher_balance_left");
        proof.proof_vec_lower_cipher_balance_right[i].Print("proof_vec_lower_cipher_balance_right");
        proof.proof_vec_lower_cipher_transfer_left[i].Print("proof_vec_lower_cipher_transfer_left");
        proof.proof_lower_cipher_transfer_right[i].Print("proof_lower_cipher_transfer_right");
        proof.proof_vec_lower_pk[i].Print("proof_vec_lower_pk");
        proof.proof_vec_lower_g[i].Print("proof_vec_lower_g");
        proof.proof_vec_lower_opposite_cipher[i].Print("proof_vec_lower_opposite_cipher");
        proof.proof_vec_lower_opposite_cipher_g[i].Print("proof_vec_lower_opposite_cipher_g");
        proof.proof_vec_eval_f0[i].Print("proof_vec_eval_f0");
        proof.proof_vec_eval_f1[i].Print("proof_vec_eval_f1");
    }
    proof.proof_Ssk.Print("proof_Ssk");
    proof.proof_Sr.Print("proof_Sr");
    proof.proof_Sb0.Print("proof_Sb0");
    proof.proof_Sb1.Print("proof_Sb1");

    proof.proof_Ay_re_encryption.Print("proof_Ay_re_encryption");
    proof.proof_AD_re_encryption.Print("proof_AD_re_encryption");
    proof.proof_Ab0_re_encryption.Print("proof_Ab0_re_encryption");
    proof.proof_Ab1_re_encryption.Print("proof_Ab1_re_encryption");
    proof.proof_Ax_re_encryption.Print("proof_Ax_re_encryption");
    proof.proof_Au.Print("proof_Au");
}

PP Setup(size_t num_cipher, size_t log_num_cipher, Pedersen::PP &com_part)
{

    PP pp;
    pp.num_cipher = num_cipher;
    pp.log_num_cipher = log_num_cipher;
    pp.com_part = com_part;
    pp.g = ECPoint(generator); 
    return pp;
}

// multiplicate the element of the vector
BigInt Accumulate(std::vector<BigInt> vec, const BigInt &mod)
{
    BigInt ans = BigInt(bn_1);
    for(auto i = 0; i < vec.size(); i++)
    {
        ans = (ans * vec[i]) % mod;
    }
    return ans;
}

// generate the linear Polynomial Product for each index i
std::vector<BigInt> BigIntPolModProduct(std::vector< std::vector<std::pair<BigInt, BigInt>> >vec_F, BigInt index, BigInt mod)
{
    size_t k = vec_F.size(); // n is the number of rows, m is the number of columns,m=2;
    size_t m = vec_F[0].size();
    std::vector<BigInt> vec_ans(k+1, bn_0);
    size_t n = (1<<k); // n=2^k;
    size_t sum=0;
    std::vector<BigInt> vec_tmp(k);
    for(auto i = 0; i < n; i++)
    {
        for(auto j = 0; j < k; j++)
        {
            if(((i >> j) & 1) ==1 )
            {
                sum++;
                vec_tmp[j] = vec_F[j][index.GetTheNthBit(j)].first;
            }
            else
            {
                vec_tmp[j] = vec_F[j][index.GetTheNthBit(j)].second;
            }

        }
        BigInt tmp_acc = Accumulate(vec_tmp, mod);
        vec_ans[sum] = (vec_ans[sum] + tmp_acc) % mod;
        sum = 0;      
    }
    return vec_ans;
}
/* generate a^n = (a^0, a^1, a^2, ..., a^{n-1}) */ 
std::vector<BigInt> GenBigIntPowerVector(size_t LEN, const BigInt &a)
{
    
    std::vector<BigInt> vec_result(LEN);
    vec_result[0] = BigInt(bn_1); 
    for (auto i = 1; i < LEN; i++)
    {
        vec_result[i] = (vec_result[i-1] * a) % order; // result[i] = result[i-1]*a % order
    }
    return vec_result; 
}
/* generate a^n = (a^0,a^0, a^1, a^2, ..., a^{n-2}) */
std::vector<BigInt> GenBigIntPowerVector4sdpt(size_t LEN, const BigInt &a)
{
    
    std::vector<BigInt> vec_result(LEN);
    vec_result[0] = BigInt(bn_1);
    vec_result[1] = BigInt(bn_1); 
    for (auto i = 2; i < LEN; i++)
    {
        vec_result[i] = (vec_result[i-1] * a) % order; // result[i] = result[i-1]*a % order
    }
    return vec_result; 
}

// circularly shifts the vector of field elements by the integer j, choose right shift 
std::vector<BigInt> Shift(std::vector<BigInt> vec, size_t j)
{
    size_t n = vec.size(); 
    std::vector<BigInt> vec_result(n); 
    for (size_t i = 0; i < n; i++)
    {
        vec_result[i] = vec[(i+j) % n]; 
    }
    return vec_result; 
}

// transposit the matrix
std::vector<std::vector<BigInt>> BigIntMatrixTransposition(std::vector<std::vector<BigInt>> vec)
{
    size_t n = vec.size();
    size_t m = vec[0].size();
    std::vector<std::vector<BigInt>> vec_result(m, std::vector<BigInt>(n));
    for(auto i = 0; i < n; i++)
    {
        for(auto j = 0; j < m; j++)
        {
            vec_result[j][i] = vec[i][j];
        }
    }
    return vec_result;
}
// get the nth bit of element
size_t GetTheNthBit(size_t index, size_t n)
{
    return (index >> n) & 1;
}

//prove the sender encrypt value is -v, receiver encrypt value is v, the index of them is opposite
void Prove(PP &pp, Witness &witness, Instance &instance, std::string &transcript_str, Proof &proof, ConsistencyRandom &consistency_random)
{

    BigInt ra = GenRandomBigIntLessThan(order); 
    BigInt rb = GenRandomBigIntLessThan(order);

    size_t n = pp.num_cipher;
    size_t m = pp.log_num_cipher;
    std::vector<BigInt> al0(m); // randomness choosed for bit commitment
    std::vector<BigInt> bl0(m); // bit representation of sender's index 
    std::vector<BigInt> al1(m); // randomness choosed for bit commitment
    std::vector<BigInt> bl1(m); // bit representation of receiver's index 
    BigInt sender_index = witness.sender_index;
    BigInt receiver_index = witness.receiver_index;

    size_t l0_size_t = sender_index.ToUint64(); // type from BigInt to size_t
    size_t l1_size_t = receiver_index.ToUint64();
    
    for(auto i = 0; i < m; i++)
    {
        al0[i] = GenRandomBigIntLessThan(order);
        al1[i] = GenRandomBigIntLessThan(order);
        if(sender_index.GetTheNthBit(i) == 1)   
        {
            bl0[i] = bn_1;
        }
        else
        {
            bl0[i] = bn_0;
        }
        if(receiver_index.GetTheNthBit(i) == 1)   
        {
            bl1[i] = bn_1;
        }
        else
        {
            bl1[i] = bn_0;
        }
    }
    consistency_random.vec_al0 = al0;
    consistency_random.vec_al1 = al1;

    // fill the element to commit
    std::vector<BigInt> vec_ma0(2*m);
    std::vector<BigInt> vec_mb0(2*m);
    std::vector<BigInt> vec_ma1(2*m);
    std::vector<BigInt> vec_mb1(2*m);
    std::vector<BigInt> vec_ma(4*m+2);
    std::vector<BigInt> vec_mb(4*m+2);

    /*fill vec_ma0 and vec_mb0, the first part*/
    std::copy(al0.begin(), al0.end(), vec_ma0.begin());
    std::copy(al1.begin(), al1.end(), vec_ma0.begin()+m);
    std::copy(bl0.begin(), bl0.end(), vec_mb0.begin());
    std::copy(bl1.begin(), bl1.end(), vec_mb0.begin()+m);

    /*fill vec_ma1*/
    std::vector<BigInt> vec_tmpa(m);
    
    BigInt mod = order;
    vec_tmpa = BigIntVectorModNegate(al0, mod);
  
    vec_tmpa = BigIntVectorModProduct(vec_tmpa, al0, order);
    std::copy(vec_tmpa.begin(), vec_tmpa.end(), vec_ma1.begin());

    vec_tmpa = BigIntVectorModNegate(al1, mod);
    vec_tmpa = BigIntVectorModProduct(vec_tmpa, al1, order);
    std::copy(vec_tmpa.begin(), vec_tmpa.end(), vec_ma1.begin()+m);

    /*fill vec_mb1*/
    std::vector<BigInt> vec_tmpb(m);
    BigInt bn2_minus = bn_2.Negate();
    std::vector<BigInt> vec_1_power(m, bn_1);
    vec_tmpb=BigIntVectorModScalar(bl0, bn2_minus, order);
 
    vec_tmpb=BigIntVectorModAdd(vec_tmpb, vec_1_power, order);
    vec_tmpb=BigIntVectorModProduct(vec_tmpb, al0, order);

    std::copy(vec_tmpb.begin(), vec_tmpb.end(), vec_mb1.begin());

    vec_tmpb=BigIntVectorModScalar(bl1, bn2_minus, order);
 
    vec_tmpb=BigIntVectorModAdd(vec_tmpb, vec_1_power, order);
    vec_tmpb=BigIntVectorModProduct(vec_tmpb, al1, order);
    std::copy(vec_tmpb.begin(), vec_tmpb.end(), vec_mb1.begin()+m);

    /*fill vec_ma and vec_mb*/
    std::copy(vec_ma0.begin(), vec_ma0.end(), vec_ma.begin());
    std::copy(vec_ma1.begin(), vec_ma1.end(), vec_ma.begin()+2*m);
    std::copy(vec_mb0.begin(), vec_mb0.end(), vec_mb.begin());
    std::copy(vec_mb1.begin(), vec_mb1.end(), vec_mb.begin()+2*m);

    vec_ma[4*m] = vec_ma[0] * vec_ma[m] % order;
    vec_ma[4*m+1] = vec_ma[4*m];
    if(vec_mb[0] == bn_1)
    {
        vec_mb[4*m] = vec_ma[m];
       
    }
    else
    {
        vec_mb[4*m] = vec_ma[0];
    }
    if(vec_mb[m] == bn_1)
    {
        vec_mb[4*m+1] = -vec_ma[m];
    }
    else
    {
        vec_mb[4*m+1] = -vec_ma[0];
    }
    
    proof.proof_commitment_A=Pedersen::Commit(pp.com_part, vec_ma, ra); //comiitment of A

    proof.proof_commitment_B=Pedersen::Commit(pp.com_part, vec_mb, rb); //commitment of B

    // linear polynomials F0(X) = b0 * X + a0 
    std::vector< std::vector< std::pair<BigInt, BigInt>> > vec_F0(m,std::vector<std::pair<BigInt, BigInt>>(2));
    // linear polynomials F1(X) = b1 * X + a1 
    std::vector< std::vector< std::pair<BigInt, BigInt>> > vec_F1(m,std::vector<std::pair<BigInt, BigInt>>(2)); 
  
    // polynomial product
    std::vector< std::vector<BigInt> > vec_P0(n,std::vector<BigInt>(m)); //n rows ,m columns
    std::vector< std::vector<BigInt> > vec_P1(n,std::vector<BigInt>(m)); //n rows ,m columns
    std::vector< std::vector<BigInt> > vec_P0transposition; //n rows ,m columns
    std::vector< std::vector<BigInt> > vec_P1transposition; //n rows ,m columns

    /*compute F and P*/
    for(auto k = 0; k < m; k++)
    {   
        std::pair<BigInt, BigInt> tmp_F0;
        std::pair<BigInt, BigInt> tmp_F1;
        tmp_F0.first = bl0[k];
        tmp_F0.second = al0[k];
        vec_F0[k][1] = tmp_F0;
        tmp_F0.first = (bn_1 - bl0[k]);
        tmp_F0.second = -al0[k];
        vec_F0[k][0] = tmp_F0;

        tmp_F1.first = bl1[k];
        tmp_F1.second = al1[k];
        vec_F1[k][1] = tmp_F1;
        tmp_F1.first = (bn_1 - bl1[k]);
        tmp_F1.second = -al1[k];
        vec_F1[k][0] = tmp_F1;
    }

    std::vector<BigInt> vec_product_tmp;
    for(auto i = 0; i < n; i++)
    {
        vec_product_tmp = BigIntPolModProduct(vec_F0,i, order);
        vec_P0[i] = vec_product_tmp; 
        vec_product_tmp = BigIntPolModProduct(vec_F1,i, order);
        vec_P1[i] = vec_product_tmp;            
    }
   
    vec_P0transposition=BigIntMatrixTransposition(vec_P0);
    vec_P1transposition=BigIntMatrixTransposition(vec_P1);

    /*compute challenge v*/
    transcript_str += proof.proof_commitment_A.ToByteString();
    transcript_str += proof.proof_commitment_B.ToByteString();
   

    BigInt v = Hash::StringToBigInt(transcript_str);

    size_t map_len = pp.num_cipher; //map_len should be equal to N;
   
    std::vector<BigInt> vec_ksi = GenBigIntPowerVector4sdpt(map_len, v);

    //sample phi, chi_k, psi_k, omega from Zq
    std::vector<BigInt> phi(m);
    std::vector<BigInt> chi(m);
    std::vector<BigInt> psi(m);
    std::vector<BigInt> omega(m);

    for(auto i=0;i<m;i++)
    {
        phi[i] = GenRandomBigIntLessThan(order);
        chi[i] = GenRandomBigIntLessThan(order);
        psi[i] = GenRandomBigIntLessThan(order);
        omega[i] = GenRandomBigIntLessThan(order);
    }

    //compute the lower-order terms 
    std::vector<ECPoint> proof_vec_lower_cipher_balance_left(m);
    std::vector<ECPoint> proof_vec_lower_cipher_balance_right(m);
    std::vector<ECPoint> proof_vec_lower_cipher_transfer_left(m);
    std::vector<ECPoint> proof_lower_cipher_transfer_right(m);
    std::vector<ECPoint> proof_vec_lower_pk(m);
    std::vector<ECPoint> proof_vec_lower_g(m);
    std::vector<ECPoint> proof_vec_lower_opposite_cipher(m);
    std::vector<ECPoint> proof_vec_lower_opposite_cipher_g(m);
    
    //in this way, ECPointVectorMul is equal to MultiExp of the paper Anonymous Zehter
    ECPoint ec_tmp;
    ECPoint ec_sum_tmp;
    
    for(size_t k = 0; k < m; k++)
    {
        proof_vec_lower_cipher_balance_left[k] = ECPointVectorMul(instance.vec_cipher_balance_left, vec_P0transposition[k]) + (instance.vec_pk[l0_size_t] * phi[k]);
        proof_vec_lower_cipher_balance_right[k] = ECPointVectorMul(instance.vec_cipher_balance_right, vec_P0transposition[k]) + (pp.g * phi[k]);
        proof_vec_lower_cipher_transfer_left[k] = ECPointVectorMul(instance.vec_cipher_transfer_left, vec_P0transposition[k]) + (instance.vec_pk[l0_size_t] * chi[k]);
        proof_lower_cipher_transfer_right[k] = (pp.g * chi[k]);
        proof_vec_lower_pk[k] = ECPointVectorMul(instance.vec_pk, vec_P0transposition[k]) + (instance.vec_pk[l0_size_t] * psi[k]);
        proof_vec_lower_g[k] = pp.g * psi[k];
        proof_vec_lower_opposite_cipher_g[k] = (pp.g * omega[k]);
        ec_sum_tmp.SetInfinity();
        //use the other way is also ok,but need to two vector addtionly 
        for(size_t l = 0; l < 2; l++)
        {
            for(size_t j = 0; j< n/2; j++)
            {
                size_t index_ka = (2*j+l) % n;
                size_t index_Pl0 = (l0_size_t+2*j) % n;
                size_t index_Pl1 = (l1_size_t+2*j) % n;
                if(l == 0)
                {
                    BigInt expont = witness.value * (-vec_P0[index_Pl0][k] + vec_P0[index_Pl1][k]);
                    ec_tmp = pp.g * expont;
                }
                else
                {
                    BigInt expont = witness.value * (-vec_P1[index_Pl0][k] + vec_P1[index_Pl1][k]);
                    ec_tmp = pp.g * expont;
                }
                ec_sum_tmp = ec_sum_tmp + ec_tmp * vec_ksi[index_ka];                
            }
        }
        proof_vec_lower_opposite_cipher[k] = ec_sum_tmp + (instance.cipher_transfer_right * omega[k]);
    }
    proof.proof_vec_lower_cipher_balance_left = proof_vec_lower_cipher_balance_left;
    proof.proof_vec_lower_cipher_balance_right = proof_vec_lower_cipher_balance_right;
    proof.proof_vec_lower_cipher_transfer_left = proof_vec_lower_cipher_transfer_left;
    proof.proof_lower_cipher_transfer_right = proof_lower_cipher_transfer_right;
    proof.proof_vec_lower_pk = proof_vec_lower_pk;
    proof.proof_vec_lower_g = proof_vec_lower_g;
    proof.proof_vec_lower_opposite_cipher = proof_vec_lower_opposite_cipher;
    proof.proof_vec_lower_opposite_cipher_g = proof_vec_lower_opposite_cipher_g;

    /*compute the challenge w*/
    //we use the parallel way to compute the challenge w, which is more efficient,if need,serial way is also ok 
    for(size_t i = 0; i < m; i++)
    {
        transcript_str += proof.proof_vec_lower_cipher_balance_left[i].ToByteString();
        transcript_str += proof.proof_vec_lower_cipher_balance_right[i].ToByteString();
        transcript_str += proof.proof_vec_lower_cipher_transfer_left[i].ToByteString();
        transcript_str += proof.proof_lower_cipher_transfer_right[i].ToByteString();
        transcript_str += proof.proof_vec_lower_pk[i].ToByteString();
        transcript_str += proof.proof_vec_lower_g[i].ToByteString();
        transcript_str += proof.proof_vec_lower_opposite_cipher[i].ToByteString();
        transcript_str += proof.proof_vec_lower_opposite_cipher_g[i].ToByteString();
    }

    BigInt w = Hash::StringToBigInt(transcript_str);
    
    proof.proof_vec_eval_f0.resize(m);
    proof.proof_vec_eval_f1.resize(m);
    for(auto k = 0; k < m; k++)
    {
        proof.proof_vec_eval_f0[k] = (bl0[k] * w % order + al0[k]) % order;
        proof.proof_vec_eval_f1[k] = (bl1[k] * w % order + al1[k]) % order;
        transcript_str += proof.proof_vec_eval_f0[k].ToByteString();
        transcript_str += proof.proof_vec_eval_f1[k].ToByteString();
    }
    proof.proof_Za=(rb * w % order + ra) % order; // Za = rB * w + rA
    
    transcript_str += proof.proof_Za.ToByteString();

    BigInt z = Hash::StringToBigInt(transcript_str);
    
    //prover "anticipates" certain re-encryptions
    BigInt w_exp_m = w.ModExp(m, order);

    // Eq (71) -- compute \overline{C_{R n}} = (C_{R n, l_{0}})^{w^{m}} \cdot (\prod_{k=0}^{m-1} g^{-\phi_{k} \cdot w^{k}})
    ECPoint re_encryption_cipher_balance_right = instance.vec_cipher_balance_right[l0_size_t] * w_exp_m ;
    BigInt w_exp_k;
    for(auto k = 0; k < m; k++)
    {
        w_exp_k = w.ModExp(k, order);
        w_exp_k = w_exp_k.ModMul(-phi[k], order);
        re_encryption_cipher_balance_right = re_encryption_cipher_balance_right + pp.g * w_exp_k;
    }

    // Eq (72)  -- compute \overline{D} = D^{w^m} \cdot g^{-\sum_{k=0}^{m-1} \chi_k \cdot w^k}
    ECPoint re_encryption_cipher_transfer_right=instance.cipher_transfer_right*w_exp_m;
    BigInt w_exp_4_g = bn_0;
    //you can also use the other way to compute 
    for(auto k=0;k<m;k++)
    {
        w_exp_k = w.ModExp(k,order);
        w_exp_4_g = (w_exp_4_g - chi[k] * w_exp_k) % order;      
    }
    re_encryption_cipher_transfer_right = re_encryption_cipher_transfer_right + pp.g * w_exp_4_g;

    BigInt w_exp = bn_0;
    for(auto k = 0; k < m; k++)
    {
        w_exp_k = w.ModExp(k,order);
        w_exp = (w_exp+psi[k] * w_exp_k) % order;      
    }
    w_exp = w_exp_m.ModSub(w_exp, order);
    ECPoint re_encryption_cipher_g = pp.g * w_exp; 

    //compute the P of eval of w
    std::vector<BigInt> vec_evalP0(n);
    std::vector<BigInt> vec_evalP1(n);

    /*the fisrt way*/
    BigInt tmp_sum_P0 = bn_0;
    BigInt tmp_sum_P1 = bn_0;
    for(auto i = 0;i < n; i++)
    {
        tmp_sum_P0 = bn_0;
        tmp_sum_P1 = bn_0;
        for(auto j = 0; j < m; j++)
        {
            tmp_sum_P0 = (tmp_sum_P0 + vec_P0[i][j] * w.ModExp(BigInt(j), order)) % order;
            tmp_sum_P1 = (tmp_sum_P1 + vec_P1[i][j] * w.ModExp(BigInt(j), order)) % order;
        }
        vec_evalP0[i] = tmp_sum_P0;
        vec_evalP1[i] = tmp_sum_P1;
    }
    /*the sender_index and receiver_index's poly order is m.not m-1,so had better to use the second way if you do not knw detail*/
    vec_evalP0[l0_size_t] = (vec_evalP0[l0_size_t] + w.ModExp(m, order)) % order;
    vec_evalP1[l1_size_t] = (vec_evalP1[l1_size_t] + w.ModExp(m, order)) % order;

    /*the second way*/
    /*BigInt tmp_sump0 = bn_1;
    BigInt tmp_sump1 = bn_1;
    for(auto i = 0; i < n; i++)
    {
        tmp_sump0 = bn_1;
        tmp_sump1 = bn_1;
        for(auto k = 0; k < m; k++)
        {
            if(GetTheNthBit(i,k) == 1)
            {
                tmp_sump0 = tmp_sump0 * proof.proof_vec_eval_f0[k] % order;
                tmp_sump1 = tmp_sump1 * proof.proof_vec_eval_f1[k] % order;
            }
            else
            {
                tmp_sump0 = tmp_sump0 * (w - proof.proof_vec_eval_f0[k]) % order;
                tmp_sump1 = tmp_sump1 * (w - proof.proof_vec_eval_f1[k]) % order;
            } 
        }
        vec_evalP0[i] = tmp_sump0;
        vec_evalP1[i] = tmp_sump1; 
    }*/

    // Eq (74) compute --
    /* \overline{y_X} = \prod_{i,j=0}^{1,\frac N2-1}\text{MultiExp} \left((y_i)_{i=0}^{N-1},
    \text{Shift}\left((P_{i,i}(w))_{i=0}^{N-1},2\cdot j\right)\right)^{\xi_{2\cdot j+\iota}}
    \cdot\left(\prod_{k=0}^{m-1}g^{-\omega_k\cdot w^k}\right)
    */
    ECPoint re_encryption_opposite_cipher;
    re_encryption_opposite_cipher.SetInfinity();
    std::vector<BigInt> vec_shift;

    for(size_t l=0; l<2; l++)
    {
        ECPoint re_tmp;
        for(size_t j = 0; j < n/2; j++)
        {
            size_t index_ka = (2*j+l) % n;
            if(l == 0)
            {
                vec_shift = Shift(vec_evalP0, 2*j);
                re_tmp=ECPointVectorMul(instance.vec_pk, vec_shift);
                
            }
            else
            {
                vec_shift = Shift(vec_evalP1, 2*j);
                re_tmp = ECPointVectorMul(instance.vec_pk, vec_shift);
                
            }
            re_encryption_opposite_cipher = re_encryption_opposite_cipher + re_tmp * vec_ksi[index_ka];  
                         
        }
    }
    for(auto k = 0; k < m; k++)
    {
        w_exp_k = w.ModExp(k, order);
        w_exp_k = w_exp_k.ModMul(-omega[k], order);
        re_encryption_opposite_cipher = re_encryption_opposite_cipher + pp.g * w_exp_k;
    }

    BigInt ksk, kr, kb, ktau;
    ksk = GenRandomBigIntLessThan(order);
    kr = GenRandomBigIntLessThan(order);
    kb = GenRandomBigIntLessThan(order);
    ktau = GenRandomBigIntLessThan(order);

    consistency_random.kb = kb;

    // Eq (75) - Eq (79)
    // compute A_{y} = \overline{g}^{k_{\mathrm{sk}}} 
    proof.proof_Ay_re_encryption = re_encryption_cipher_g * ksk;
    // compute A_{D} = g^{k_{r}}
    proof.proof_AD_re_encryption = pp.g * kr;
    
    BigInt zsquare = z * z % order; 
    BigInt zcube = zsquare * z% order;
    // compute A_{b} = g^{k_{b}} \cdot (\overline{D}^{-z^{2}})^{k_{\mathrm{sk}}}
    proof.proof_Ab0_re_encryption = pp.g * kb + ((re_encryption_cipher_transfer_right) * (-zsquare)) * ksk;
    // compute A_{b} = g^{k_{b}} \cdot \overline{{C_{Rn}}}z^{3})^{k_{\mathrm{sk}}}
    proof.proof_Ab1_re_encryption = pp.g * kb + ((re_encryption_cipher_balance_right) * (zcube)) * ksk;
    // compute A_{X} = \overline{{y_{X}}}k_{r} 
    proof.proof_Ax_re_encryption = re_encryption_opposite_cipher * kr;
    // A_{u} = g_{\mathrm{epoch}}^{k_{\mathrm{sk}}}
    proof.proof_Au = instance.gepoch * ksk;

    transcript_str += proof.proof_Ay_re_encryption.ToByteString();
    transcript_str += proof.proof_AD_re_encryption.ToByteString();
    transcript_str += proof.proof_Ab0_re_encryption.ToByteString();
    transcript_str += proof.proof_Ab1_re_encryption.ToByteString();
    transcript_str += proof.proof_Ax_re_encryption.ToByteString();
    transcript_str += proof.proof_Au.ToByteString();
   
    BigInt c = Hash::StringToBigInt(transcript_str);

    BigInt w_exp_m_times_c = w_exp_m * c % order;
    proof.proof_Ssk = (ksk + c * witness.sk) % order; // S_sk = k_sk + c * sk
    proof.proof_Sr = (kr + c * witness.r) % order; // S_r = k_r + c * r
    proof.proof_Sb0 = (kb + ((w_exp_m_times_c * witness.value) % order) * zsquare) % order; // S_b0 = k_b + c * w^m * z^2 * v
    proof.proof_Sb1 = (kb + ((w_exp_m_times_c * witness.vprime) % order) * zcube) % order; // S_b1 = k_b + c * w^m * z^3 * vprime
    
    #ifdef DEBUG
        std::cout << "MOOM prove Succeeds >>>" << std::endl; 
    #endif
    
    std::cout<<"Many_Out_Of_Many proof Success "<<std::endl;
    
}

bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    
    size_t n = pp.num_cipher;
    size_t m = pp.log_num_cipher;
    // initialize the transcript
    transcript_str = "";
    transcript_str += proof.proof_commitment_A.ToByteString();
    transcript_str += proof.proof_commitment_B.ToByteString();

    // recover the challenge v
    BigInt v = Hash::StringToBigInt(transcript_str);

    std::vector<BigInt> vec_p0(n);
    std::vector<BigInt> vec_p1(n);

    for(auto i = 0; i < m; i++)
    {
        transcript_str += proof.proof_vec_lower_cipher_balance_left[i].ToByteString();
        transcript_str += proof.proof_vec_lower_cipher_balance_right[i].ToByteString();
        transcript_str += proof.proof_vec_lower_cipher_transfer_left[i].ToByteString();
        transcript_str += proof.proof_lower_cipher_transfer_right[i].ToByteString();
        transcript_str += proof.proof_vec_lower_pk[i].ToByteString();
        transcript_str += proof.proof_vec_lower_g[i].ToByteString();
        transcript_str += proof.proof_vec_lower_opposite_cipher[i].ToByteString();
        transcript_str += proof.proof_vec_lower_opposite_cipher_g[i].ToByteString();
    }

    // recover the challenge v
    BigInt w = Hash::StringToBigInt(transcript_str);
    
    // compute the product of the eval of evaluations of linear polynomials F0(X) = b0 * X + a0 at the verifiers challenge x
    BigInt tmp_p0 = bn_1;
    for(auto i = 0; i < n; i++)
    {
        tmp_p0 = bn_1;
        for(auto k = 0; k < m; k++)
        {
            if(GetTheNthBit(i,k) == 1)
            {
                tmp_p0=  tmp_p0 * proof.proof_vec_eval_f0[k] % order;        
            }
            else
            {
                tmp_p0 = (tmp_p0 * ((w - proof.proof_vec_eval_f0[k]) % order) % order) % order;
            }
        }
        vec_p0[i] = tmp_p0 % order;      
    }
    
    BigInt tmp_p1 = bn_1;
    for(auto i = 0; i < n; i++)
    {
        tmp_p1 = bn_1;
        for(auto k = 0; k < m; k++)
        {
            if(GetTheNthBit(i,k) == 1)
            {
                tmp_p1 = tmp_p1 * proof.proof_vec_eval_f1[k] % order;        
            }
            else
            {
                tmp_p1 = tmp_p1 * (w - proof.proof_vec_eval_f1[k]) % order;
            }
        }
        vec_p1[i] = tmp_p1 % order;      
    }

    std::vector<BigInt> vec_move_f(4*m+2);
    std::cout << "begin to fill the commitment terms" << std::endl;
    std::vector<BigInt> vec_move_f_tmp_4_f0(m);
    for(auto i = 0; i < m; i++)
    {
        vec_move_f_tmp_4_f0[i] = proof.proof_vec_eval_f0[i] * ((w - proof.proof_vec_eval_f0[i] + order) % order) % order;
    }

    std::vector<BigInt> vec_move_f_tmp_4_f1(m);
    for(auto i = 0; i < m; i++)
    {
        vec_move_f_tmp_4_f1[i] = proof.proof_vec_eval_f1[i] * ((w - proof.proof_vec_eval_f1[i] + order) % order) % order;
    }
   
    std::copy(proof.proof_vec_eval_f0.begin(), proof.proof_vec_eval_f0.end(), vec_move_f.begin());
    std::copy(proof.proof_vec_eval_f1.begin(), proof.proof_vec_eval_f1.end(), vec_move_f.begin()+m);
    std::copy(vec_move_f_tmp_4_f0.begin(), vec_move_f_tmp_4_f0.end(), vec_move_f.begin()+2*m);
    std::copy(vec_move_f_tmp_4_f1.begin(), vec_move_f_tmp_4_f1.end(), vec_move_f.begin()+3*m);
    PrintSplitLine('-');
    std::cout << "success fill the commitment terms" << std::endl;
    vec_move_f[4*m] = vec_move_f[0] * vec_move_f[m] % order;
    vec_move_f[4*m+1] = (((w - vec_move_f[0]) % order) * ((w - vec_move_f[m]) % order)) % order;

    std::cout << "begin to check" << std::endl;
    //check 1 the commitment
    ECPoint COM_LFET = proof.proof_commitment_A + proof.proof_commitment_B * w;
    ECPoint COM_RIGHT= Pedersen::Commit(pp.com_part, vec_move_f, proof.proof_Za);
    if(COM_LFET != COM_RIGHT)
    {
        std::cout << "Commitment is wrong" << std::endl;
        return false;
    }
    else{
        std::cout << "Commitment is right" << std::endl;
    }
    
    //begin re-encryptions
    ECPoint re_encryption_cipher_balance_left = ECPointVectorMul(instance.vec_cipher_balance_left, vec_p0);
    ECPoint re_encryption_cipher_balance_right = ECPointVectorMul(instance.vec_cipher_balance_right, vec_p0);
    ECPoint re_encryption_cipher_transfer_left = ECPointVectorMul(instance.vec_cipher_transfer_left, vec_p0);
    BigInt w_exp_m = w.ModExp(m, order);
    ECPoint re_encryption_cipher_transfer_right = instance.cipher_transfer_right * w_exp_m;
    ECPoint re_encryption_pk = ECPointVectorMul(instance.vec_pk, vec_p0);
    ECPoint re_encryption_cipher_g = pp.g * w_exp_m;

    BigInt w_exp_k;
    for(auto k = 0; k < m; k++)
    {
        w_exp_k = w.ModExp(k, order);
        re_encryption_cipher_balance_left = re_encryption_cipher_balance_left + (proof.proof_vec_lower_cipher_balance_left[k] * (-w_exp_k));
        re_encryption_cipher_balance_right = re_encryption_cipher_balance_right + (proof.proof_vec_lower_cipher_balance_right[k] * (-w_exp_k));
        re_encryption_cipher_transfer_left = re_encryption_cipher_transfer_left + (proof.proof_vec_lower_cipher_transfer_left[k] * (-w_exp_k));
        re_encryption_cipher_transfer_right = re_encryption_cipher_transfer_right + (proof.proof_lower_cipher_transfer_right[k] * (-w_exp_k));
        re_encryption_pk = re_encryption_pk + (proof.proof_vec_lower_pk[k] * (-w_exp_k));
        re_encryption_cipher_g = re_encryption_cipher_g + (proof.proof_vec_lower_g[k] * (-w_exp_k));
    }

    std::vector<BigInt> vec_ksi=GenBigIntPowerVector4sdpt(n, v);

    ECPoint re_encryption_opposite_cipher;
    re_encryption_opposite_cipher.SetInfinity();
    ECPoint re_encryption_opposite_cipher_g;
    re_encryption_opposite_cipher_g.SetInfinity();

    std::vector<BigInt> vec_shift1;
    std::vector<BigInt> vec_shift2;
    for(size_t l = 0; l < 2; l++)
    {
        ECPoint re_tmp0;
        ECPoint re_tmp1;
        for(size_t j = 0; j < n/2; j++)
        {
            size_t index_ka = (2*j+l) % n;
            if(l == 0)
            {
                vec_shift1 = Shift(vec_p0, 2*j);
                re_tmp0 = ECPointVectorMul(instance.vec_cipher_transfer_left, vec_shift1);
                re_tmp1 = ECPointVectorMul(instance.vec_pk, vec_shift1);
            }
            else
            {
                vec_shift2 = Shift(vec_p1, 2*j);
                re_tmp0 = ECPointVectorMul(instance.vec_cipher_transfer_left, vec_shift2);
                re_tmp1 = ECPointVectorMul(instance.vec_pk, vec_shift2);
            }
            re_encryption_opposite_cipher = re_encryption_opposite_cipher + re_tmp0 * vec_ksi[index_ka];
            re_encryption_opposite_cipher_g = re_encryption_opposite_cipher_g + re_tmp1 * vec_ksi[index_ka];
        }
        
    }

    for(auto k = 0; k < m; k++)
    {
        w_exp_k = w.ModExp(k,order);
        re_encryption_opposite_cipher = re_encryption_opposite_cipher + (proof.proof_vec_lower_opposite_cipher[k] * (-w_exp_k));
        re_encryption_opposite_cipher_g = re_encryption_opposite_cipher_g + (proof.proof_vec_lower_opposite_cipher_g[k] * (-w_exp_k));
    }
    
    //compute the challenge z
    for(auto k = 0; k < m; k++)
    {
        transcript_str += proof.proof_vec_eval_f0[k].ToByteString();
        transcript_str += proof.proof_vec_eval_f1[k].ToByteString();
    }
    transcript_str += proof.proof_Za.ToByteString();

    BigInt z = Hash::StringToBigInt(transcript_str);
    BigInt zsquare= z  *z % order; 
    BigInt zcube= zsquare * z % order;

    //compute the challenge c
    transcript_str += proof.proof_Ay_re_encryption.ToByteString();
    transcript_str += proof.proof_AD_re_encryption.ToByteString();
    transcript_str += proof.proof_Ab0_re_encryption.ToByteString();
    transcript_str += proof.proof_Ab1_re_encryption.ToByteString();
    transcript_str += proof.proof_Ax_re_encryption.ToByteString();
    transcript_str += proof.proof_Au.ToByteString();
   
    BigInt c = Hash::StringToBigInt(transcript_str);

    //check Ay 
    bool Validity = true;
    ECPoint re_encryption_Ay_right = re_encryption_cipher_g * (proof.proof_Ssk) + re_encryption_pk * (-c);
    
    if(re_encryption_Ay_right != proof.proof_Ay_re_encryption){
        std::cout << "Ay check is wrong " << std::endl;
        Validity = false;
        
    }
    //check AD 
    ECPoint re_encryption_AD_right = pp.g * (proof.proof_Sr) + instance.cipher_transfer_right * (-c);
    if(re_encryption_AD_right != proof.proof_AD_re_encryption){
        std::cout << "AD check is wrong " << std::endl;
        Validity = false;
       
    }
    //check Ab0
    ECPoint re_encryption_Ab0_right = pp.g * (proof.proof_Sb0)+(re_encryption_cipher_transfer_right * (-zsquare)) * (proof.proof_Ssk) + (re_encryption_cipher_transfer_left * (-zsquare)) * (-c);
    if(re_encryption_Ab0_right != proof.proof_Ab0_re_encryption){
        std::cout << "Ab0 check is wrong " << std::endl;
        Validity = false;
        
    }
    //check Ab1
    ECPoint re_encryption_Ab1_right = pp.g * (proof.proof_Sb1) + (re_encryption_cipher_balance_right * (zcube)) * (proof.proof_Ssk) + (re_encryption_cipher_balance_left * (zcube)) * (-c);
    if(re_encryption_Ab1_right != proof.proof_Ab1_re_encryption){
        std::cout << "Ab1 check is wrong " << std::endl;
        Validity = false;
       
    }
    
    //check Ax
    ECPoint re_encryption_Ax_right = re_encryption_opposite_cipher * (-c) + re_encryption_opposite_cipher_g * (proof.proof_Sr);
    if(re_encryption_Ax_right != proof.proof_Ax_re_encryption){
        std::cout << "Ax check is wrong " << std::endl;
        Validity = false;     
    }
     //check Au
    ECPoint re_encryption_Au_right = instance.gepoch * (proof.proof_Ssk) + instance.uepoch * (-c);
    if(re_encryption_Au_right != proof.proof_Au){
        std::cout << "Au check is wrong " << std::endl;
        Validity = false;
       
    }


    if (Validity){ 
        std::cout << "proof of many_out_of_many proof accepts >>>" << std::endl; 
    }
    else{
        std::cout << "proof of many_out_of_many proof rejects >>>" << std::endl; 
    }
    return Validity;

}

}
#endif