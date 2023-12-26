/***********************************************************************************
this hpp implements the merge of (relation R1 and R2) in ESORICS 2015
Short Accountable Ring Signatures Based on DDH
by replacing ElGamal with twisted ElGamal
***********************************************************************************/
#ifndef NIZK_ENC_RELATION_HPP_
#define NIZK_ENC_RELATION_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/twisted_exponential_elgamal.hpp"
#include "../../commitment/pedersen.hpp"
#include "../../utility/polymul.hpp"


namespace EncRelation{

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    Pedersen::PP com_part;
    TwistedExponentialElGamal::PP enc_part;  
    size_t n, m; 
};

// structure of instance (pk_1,...,pk_n, Xi = pk_i^r, Y = g^r h^v)
struct Instance
{
    std::vector<TwistedExponentialElGamal::CT> vec_CT; // N ciphertexts: one constains encryption of 0  
    ECPoint ek; 
};

// structure of witness 
struct Witness
{
    size_t l;  // l \in [N]
    BigInt r; 
};


// structure of proof 
struct Proof
{
    ECPoint B; 
    BigInt z;
    std::vector<TwistedExponentialElGamal::CT> vec_G; 
    // proof of bit constraint
    ECPoint A, C, D; 
    std::vector<BigInt> vec_f; 
    BigInt zA, zC; 
};
 

/* Setup algorithm */ 
PP Setup(Pedersen::PP &com_pp, TwistedExponentialElGamal::PP &enc_pp, size_t n)
{ 
    PP pp; 
    pp.com_part = com_pp;
    pp.enc_part = enc_pp; 
    pp.n = n;
    pp.m = log(pp.com_part.N_max)/log(pp.n); // the default value 

    return pp; 
}


std::vector<size_t> Decompose(size_t l, size_t n, size_t m)
{
    std::vector<size_t> vec_index(m); 
    for(auto j = 0; j < m; j++){
        vec_index[j] = l % n;  
        l = l / n; 
    }
    return vec_index;  
}  

Proof Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str)
{    
    Proof proof;
    size_t N = instance.vec_CT.size();
    pp.m = log(N)/log(pp.n);

    std::vector<size_t> vec_index_star = Decompose(witness.l, pp.n, pp.m);     
    
    // expand to 1-dimention vector
    std::vector<BigInt> vec_delta; 
    for(auto j = 0; j < pp.m; j++){
        std::vector<BigInt> column_delta(pp.n, bn_0); 
        column_delta[vec_index_star[j]] = bn_1; 
        vec_delta.insert(vec_delta.end(), column_delta.begin(), column_delta.end());
    }
    BigInt rB = GenRandomBigIntLessThan(order); 
    proof.B = Pedersen::Commit(pp.com_part, vec_delta, rB); 


    // generate the proof for bit constraint of vec_delta
    BigInt rA = GenRandomBigIntLessThan(order); 

    std::vector<BigInt> vec_a; 
    for(auto j = 0; j < pp.m; j++){
        std::vector<BigInt> column_a = GenRandomBigIntVectorLessThan(pp.n, order); 
        column_a[0] = bn_0; 
        // set a_j,0 = - sum a_j, i
        for(auto i = 1; i < pp.n; i++){
            column_a[0] += -column_a[i];
        }
        vec_a.insert(vec_a.end(), column_a.begin(), column_a.end());
    }
    proof.A = Pedersen::Commit(pp.com_part, vec_a, rA);

    BigInt rC = GenRandomBigIntLessThan(order);
    std::vector<BigInt> vec_c;
    vec_c.resize(pp.m * pp.n);  
    for(auto i = 0; i < pp.m*pp.n; i++){
        vec_c[i] = vec_a[i] * (bn_1 - bn_2 * vec_delta[i]);
    }
    proof.C = Pedersen::Commit(pp.com_part, vec_c, rC);

    BigInt rD = GenRandomBigIntLessThan(order); 
    std::vector<BigInt> vec_d;
    vec_d.resize(pp.m * pp.n);  
    for(auto i = 0; i < pp.m * pp.n; i++){
        vec_d[i] = - vec_a[i] * vec_a[i];
    }
    proof.D = Pedersen::Commit(pp.com_part, vec_d, rD);

    transcript_str += proof.B.ToByteString(); 
    transcript_str += proof.A.ToByteString();
    transcript_str += proof.C.ToByteString();
    transcript_str += proof.D.ToByteString(); 

    // compute the challenge
    BigInt x = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    // compute the response     
    proof.vec_f.resize(pp.m * pp.n); 
    for(auto i = 0; i < pp.m * pp.n; i++){
        proof.vec_f[i] = vec_delta[i] * x + vec_a[i];
    }
    proof.zA = (rB * x + rA) % order; 
    proof.zC = (rC * x + rD) % order; 

    std::vector<BigInt> vec_rho = GenRandomBigIntVectorLessThan(pp.m, order);

    proof.vec_G.resize(pp.m);
    std::vector<TwistedExponentialElGamal::CT> vec_mask_CT(pp.m);
    ECPoint m; 
    m.SetInfinity(); 
    for(auto i = 0; i < pp.m; i++){
        vec_mask_CT[i] = TwistedExponentialElGamal::Enc(pp.enc_part, instance.ek, m, vec_rho[i]); 
    }

    // prepare the polynomial p(i)
    std::vector<std::vector<BigInt>> P; 

    for(auto i = 0; i < N; i++){
        std::vector<std::vector<BigInt>> A(pp.m, std::vector<BigInt>(2));        
        // prepare m ploynomial of form ax+b
        std::vector<size_t> vec_index = Decompose(i, pp.n, pp.m); 
 
        for(auto j = 0; j < pp.m; j++){        
            A[j][0] = vec_a[j * pp.n + vec_index[j]]; // index[j] = i_j
            if(vec_index_star[j] == vec_index[j]) A[j][1] = bn_1;
            else A[j][1] = bn_0;    
        } 
        std::vector<BigInt> p_i = PolyMul(A);     
        P.emplace_back(p_i); 
    }

    for(auto k = 0; k < pp.m; k++){
        for(auto i = 0; i < N; i++){
            TwistedExponentialElGamal::CT temp_ct = TwistedExponentialElGamal::ScalarMul(instance.vec_CT[i], P[i][k]); 
            proof.vec_G[k] = TwistedExponentialElGamal::HomoAdd(proof.vec_G[k], temp_ct);
        }
        proof.vec_G[k] = TwistedExponentialElGamal::HomoAdd(proof.vec_G[k], vec_mask_CT[k]);
    }

    std::vector<BigInt> exp_x(pp.m+1);
    exp_x[0] = bn_1;  
    for(auto k = 1; k <= pp.m; k++){
        exp_x[k] = exp_x[k-1] * x; 
    }
    proof.z = witness.r * exp_x[pp.m]; 

    for(auto k = 0; k < pp.m; k++){
        proof.z -= vec_rho[k] * exp_x[k]; 
    }

    return proof;

}


// check NIZK proof PI for Ci = Enc(pki, m; r) the witness is (r1, r2, m)
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{    
    size_t N = instance.vec_CT.size();
    pp.m = log(N)/log(pp.n);
    
    transcript_str += proof.B.ToByteString(); 
    transcript_str += proof.A.ToByteString();
    transcript_str += proof.C.ToByteString();
    transcript_str += proof.D.ToByteString(); 

    // compute the challenge
    BigInt x = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    std::vector<bool> vec_condition(4, true);
    // check condition 1
    for(auto j = 0; j < pp.m; j++){
        BigInt right = x; 
        for(auto i = 1; i < pp.n; i++){
            right += -proof.vec_f[j * pp.n + i]; 
        }
        if(proof.vec_f[j * pp.n] != right) vec_condition[0] = false;
    }

    // check condition 2
    ECPoint LEFT, RIGHT; 
    LEFT = proof.B * x + proof.A; 
    RIGHT = Pedersen::Commit(pp.com_part, proof.vec_f, proof.zA);
    vec_condition[1] = (LEFT==RIGHT);  

    // check condition 3
    std::vector<BigInt> vec_temp; 
    vec_temp.resize(pp.m * pp.n); 
    for(auto i = 0; i < pp.m * pp.n; i++){
        vec_temp[i] = proof.vec_f[i] * (x - proof.vec_f[i]); 
    }
    LEFT = proof.C * x + proof.D; 
    RIGHT = Pedersen::Commit(pp.com_part, vec_temp, proof.zC);
    vec_condition[2] = (LEFT==RIGHT);  


    // check condition 3
    ECPoint m; 
    m.SetInfinity();
    TwistedExponentialElGamal::CT ct_right = TwistedExponentialElGamal::Enc(pp.enc_part, instance.ek, m, proof.z);  
    TwistedExponentialElGamal::CT ct_left; 
    ct_left.X.SetInfinity();
    ct_left.Y.SetInfinity();

    std::vector<TwistedExponentialElGamal::CT> vec_CT(N); 
    for(auto i = 0; i < N; i++){
        BigInt product = bn_1; 
        std::vector<size_t> vec_index = Decompose(i, pp.n, pp.m);
        for(auto j = 0; j < pp.m; j++){
            product = (product * proof.vec_f[j*pp.n + vec_index[j]]) % order;
        }
        vec_CT[i] = TwistedExponentialElGamal::ScalarMul(instance.vec_CT[i], product); 
        ct_left = TwistedExponentialElGamal::HomoAdd(ct_left, vec_CT[i]);
    }

    std::vector<BigInt> exp_x(pp.m);
    exp_x[0] = bn_1;  
    for(auto k = 1; k < pp.m; k++){
        exp_x[k] = exp_x[k-1] * x; 
    }

    for(auto k = 0; k < pp.m; k++){
        TwistedExponentialElGamal::CT ct_temp = TwistedExponentialElGamal::ScalarMul(proof.vec_G[k], exp_x[k]); 
        ct_left = TwistedExponentialElGamal::HomoSub(ct_left, ct_temp);
    }


    vec_condition[3] = (ct_left == ct_right); 

    bool Validity = vec_condition[0] && vec_condition[1] && vec_condition[2] && vec_condition[3]; 


    #ifdef DEBUG
    for(auto i = 0; i < 4; i++){
        std::cout << std::boolalpha << "Condition "<< std::to_string(i) <<" (enc relation proof) = " 
                  << vec_condition[i] << std::endl; 
    }

    if (Validity){ 
        std::cout << "NIZK proof for enc relation accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZK proof for enc relation rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}

}

#endif



