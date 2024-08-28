/***********************************************************************************
this hpp implements aggregated logarithmic size Sigma_Bulletproofs  
***********************************************************************************/
#ifndef SIGMAL_BULLET_PROOF_HPP_
#define SIGMAL_BULLET_PROOF_HPP_

#include "innerproduct_proof.hpp" 
#include "../nizk/nizk_many_out_of_many.hpp"

namespace SigmaBullet{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define the structure of Sigma_Bulletproofs
struct PP
{
    size_t RANGE_LEN; 
    size_t LOG_RANGE_LEN; 
    size_t MAX_AGG_NUM; // number of sub-argument (for now, we require m to be the power of 2)

    ECPoint g, h;
    ECPoint u; // used for inside innerproduct statement
    std::vector<ECPoint> vec_g, vec_h; // the pp of innerproduct part    
};


std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.RANGE_LEN << pp.LOG_RANGE_LEN << pp.MAX_AGG_NUM; 
    fout << pp.g << pp.h << pp.u; 
    //vector serialization has been defined before
    fout << pp.vec_g;
    fout << pp.vec_h;
    return fout;
}

std::ifstream &operator>>(std::ifstream &fin, PP& pp)
{
    fin >> pp.RANGE_LEN >> pp.LOG_RANGE_LEN >> pp.MAX_AGG_NUM; 
    fin >> pp.g >> pp.h >> pp.u;
    pp.vec_g.resize(pp.RANGE_LEN * pp.MAX_AGG_NUM); 
    pp.vec_h.resize(pp.RANGE_LEN * pp.MAX_AGG_NUM); 
    fin >> pp.vec_g;
    fin >> pp.vec_h;
    return fin;  
}

struct Instance
{
    // actually no instance here
    std::vector<ECPoint> cipher_transfer_left; // Eigamal transfer cipher left part
    std::vector<ECPoint> cipher_transfer_right; // Eigamal transfer cipher right part
    std::vector<ECPoint> cipher_balance_left; // Eigamal balance cipher value part
    std::vector<ECPoint> cipher_balance_right; // Eigamal balance cipher value part
}; 

struct Witness
{
    std::vector<BigInt> v; // length = AGG_NUM
}; 

struct Proof
{
    ECPoint A, S, T1, T2;  
    BigInt taux, mu, tx; 
    ECPoint At;
    BigInt stau;
    InnerProduct::Proof ip_proof;    
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A << proof.S << proof.T1 << proof.T2;
    fout << proof.taux << proof.mu << proof.tx;
    fout << proof.At << proof.stau; 
    fout << proof.ip_proof; 
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A >> proof.S >> proof.T1 >> proof.T2;
    fin >> proof.taux >> proof.mu >> proof.tx;
    fin >> proof.At >> proof.stau; 
    fin >> proof.ip_proof;
    return fin; 
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

void PrintProof(Proof &proof)
{
    proof.A.Print("proof.A"); 
    proof.S.Print("proof.S"); 
    proof.T1.Print("proof.T1");  
    proof.T2.Print("proof.T2");  
    proof.taux.Print("proof.taux"); 
    proof.mu.Print("proof.mu"); 
    proof.tx.Print("proof.tx"); 
    proof.At.Print("proof.At");
    proof.stau.Print("proof.stau");

    InnerProduct::PrintProof(proof.ip_proof); 
}

std::string ProofToByteString(Proof &proof)
{
    std::string str;
    str += proof.A.ToByteString() + proof.S.ToByteString() + proof.T1.ToByteString() + proof.T2.ToByteString();
    str += proof.taux.ToByteString() + proof.mu.ToByteString() + proof.tx.ToByteString(); 
    str += proof.At.ToByteString() + proof.stau.ToByteString();
    str += InnerProduct::ProofToByteString(proof.ip_proof);
    return str;  
}

PP Setup(size_t &RANGE_LEN, size_t &MAX_AGG_NUM)
{
    PP pp; 
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = size_t(log2(RANGE_LEN)); 
    pp.MAX_AGG_NUM = MAX_AGG_NUM; 
    pp.g = generator; 
    pp.h = Hash::StringToECPoint(pp.g.ToByteString()); 
    pp.u = GenRandomGenerator();
    pp.vec_g = GenRandomECPointVector(RANGE_LEN * MAX_AGG_NUM);
    pp.vec_h = GenRandomECPointVector(RANGE_LEN * MAX_AGG_NUM);
    return pp; 
}

// statement C_\ell = g^-v pk_\ell^v and v \in [0, 2^n-1]
void Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str, 
                            Proof &proof,ManyOutOfMany::ConsistencyRandom consistency_random, ManyOutOfMany::Proof &many_out_of_many_proof)
{ 
    transcript_str = "";
    transcript_str += many_out_of_many_proof.proof_commitment_A.ToByteString();
    transcript_str += many_out_of_many_proof.proof_commitment_B.ToByteString();  
    BigInt v = Hash::StringToBigInt(transcript_str);
    size_t m = many_out_of_many_proof.proof_vec_lower_cipher_balance_left.size();
    std::cout << "Log_mom_proof.Num = " << m << std::endl;
    for(size_t i = 0; i < m; i++)
    {
        transcript_str += many_out_of_many_proof.proof_vec_lower_cipher_balance_left[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_cipher_balance_right[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_cipher_transfer_left[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_lower_cipher_transfer_right[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_pk[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_g[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_opposite_cipher[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_opposite_cipher_g[i].ToByteString();
    }
    BigInt w = Hash::StringToBigInt(transcript_str);
    for(size_t k = 0; k < m; k++)
    {
        transcript_str += many_out_of_many_proof.proof_vec_eval_f0[k].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_eval_f1[k].ToByteString();
    }
    transcript_str += many_out_of_many_proof.proof_Za.ToByteString();
    BigInt z = Hash::StringToBigInt(transcript_str);
    transcript_str += many_out_of_many_proof.proof_Ay_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_AD_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab0_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab1_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ax_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Au.ToByteString();
    BigInt c = Hash::StringToBigInt(transcript_str);

    auto start_time = std::chrono::steady_clock::now(); 
    size_t n = witness.v.size();
    size_t LEN = pp.RANGE_LEN * n; // LEN = mn
    std::vector<BigInt> vec_aL(LEN);  
    std::vector<BigInt> vec_aR(LEN);
    std::vector<BigInt> vec_1_power(LEN, bn_1); // vec_unary = 1^nm

    for (auto i = 0; i < n; i++)
    {
        for(auto j = 0; j < pp.RANGE_LEN; j++)
        {
            if(witness.v[i].GetTheNthBit(j) == 1)
            {
                vec_aL[i * pp.RANGE_LEN + j] = bn_1;  
            }
            else
            {
                vec_aL[i * pp.RANGE_LEN + j] = bn_0; 
            } 
        }
    }

    vec_aR = BigIntVectorModSub(vec_aL, vec_1_power,  BigInt(order)); // Eq (42) -- aR = aL - 1^n

    // prepare vec_A and vec_a for multi-exponention (used hereafter)
    
    // Eq (44) -- compute A = H^alpha g^aL h^aR (commitment to aL and aR)
    BigInt alpha = GenRandomBigIntLessThan(order); 

    std::vector<ECPoint> vec_A(2*LEN+1); 
    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+LEN, vec_A.begin()); 
    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+LEN, vec_A.begin()+LEN); 
    vec_A[2*LEN] = pp.h; 

    std::vector<BigInt> vec_a(2*LEN+1); 
    std::copy(vec_aL.begin(), vec_aL.begin()+LEN, vec_a.begin()); 
    std::copy(vec_aR.begin(), vec_aR.begin()+LEN, vec_a.begin()+LEN); 
    vec_a[2*LEN] = alpha;

    proof.A = ECPointVectorMul(vec_A, vec_a); // Eq (44) 

    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    std::vector<BigInt> vec_sL = GenRandomBigIntVectorLessThan(LEN, order); 
    std::vector<BigInt> vec_sR = GenRandomBigIntVectorLessThan(LEN, order); 
    
    // Eq (47) compute S = H^alpha g^aL h^aR (commitment to sL and sR)
    BigInt rho = GenRandomBigIntLessThan(order); 

    std::copy(vec_sL.begin(), vec_sL.end(), vec_a.begin()); 
    std::copy(vec_sR.begin(), vec_sR.end(), vec_a.begin()+LEN); 
    vec_a[2*LEN] = rho; 

    proof.S = ECPointVectorMul(vec_A, vec_a); // Eq (47) 

    // compute y and z
    // the way to generate y and z is not same as the bullet_proof
    transcript_str += proof.A.ToByteString(); 
    transcript_str += proof.S.ToByteString(); 
    transcript_str += z.ToByteString(); //  // z is the challenge generated in the many_out_of_many proof
    BigInt y = Hash::StringToBigInt(transcript_str);

    BigInt y_inverse = y.ModInverse(order);
     
    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(LEN, y_inverse); // y^{-i+1}

    BigInt z_square = z.ModSquare(order);
    BigInt z_cubic = (z * z_square) % order;
    
    std::vector<BigInt> vec_adjust_z_power(n+1); // generate z^{j+1} j \in [n] 
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= n; j++)
    {
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; //pow(z, j+1, q); description below Eq (71)
    }  

    // prepare the vector polynomials
    
    // compute l(X) Eq (70)
    std::vector<BigInt> vec_z_unary(LEN, z); // z \cdot 1^nm

    std::vector<BigInt> poly_ll0 = BigIntVectorModSub(vec_aL, vec_z_unary, BigInt(order));  
    std::vector<BigInt> poly_ll1(LEN); 
    poly_ll1.assign(vec_sL.begin(), vec_sL.end()); 

    // compute r(X)     
    std::vector<BigInt> vec_y_power = GenBigIntPowerVector(LEN, y); // y^nm
    std::vector<BigInt> vec_zz_temp = BigIntVectorModAdd(vec_z_unary, vec_aR, BigInt(order)); // vec_t = aR + z1^nm
    std::vector<BigInt> poly_rr0 = BigIntVectorModProduct(vec_y_power, vec_zz_temp, BigInt(order)); // y^nm(aR + z1^nm)
    
    std::vector<BigInt> vec_short_2_power = GenBigIntPowerVector(pp.RANGE_LEN, bn_2); // 2^n

    for (auto j = 1; j <= n; j++)
    {
        for (auto i = 0; i < (j-1)*pp.RANGE_LEN; i++) 
            vec_zz_temp[i] = bn_0; 
        for (auto i = 0; i < pp.RANGE_LEN; i++) 
            vec_zz_temp[(j-1)*pp.RANGE_LEN+i] = vec_short_2_power[i]; 
        for (auto i = 0; i < (n-j)*pp.RANGE_LEN; i++) 
            vec_zz_temp[j*pp.RANGE_LEN+i] = bn_0;

        vec_zz_temp = BigIntVectorModScalar(vec_zz_temp, vec_adjust_z_power[j], BigInt(order)); 
        poly_rr0 = BigIntVectorModAdd(poly_rr0, vec_zz_temp, BigInt(order));  
    }
    std::vector<BigInt> poly_rr1 = BigIntVectorModProduct(vec_y_power, vec_sR, BigInt(order)); //y^nsR X

    // compute t(X) 
    BigInt t0 = BigIntVectorModInnerProduct(poly_ll0, poly_rr0, BigInt(order)); 
    BigInt bn_temp1 = BigIntVectorModInnerProduct(poly_ll1, poly_rr0, BigInt(order)); 
    BigInt bn_temp2 = BigIntVectorModInnerProduct(poly_ll0, poly_rr1, BigInt(order));
    BigInt t1 = (bn_temp1 + bn_temp2) % BigInt(order);  
  
    BigInt t2 = BigIntVectorModInnerProduct(poly_ll1, poly_rr1, BigInt(order)); 

    // Eq (53) -- commit to t1, t2
    // P picks tau1 and tau2
    BigInt tau1 = GenRandomBigIntLessThan(order); 
    BigInt tau2 = GenRandomBigIntLessThan(order); 

    vec_A.clear(); vec_A = {pp.g, pp.h};
    
    //the generator is g, h, not h, g; it is not the same as the twisted elgamal
    vec_a.clear(); vec_a = { t1,tau1};
    proof.T1 = ECPointVectorMul(vec_A, vec_a); //pp.g * tau1 + pp.h * t1; mul(tau1, pp.g, t1, pp.h);
    
    //vec_a.clear(); vec_a = {tau2, t2}; 
    vec_a.clear(); vec_a = {t2,tau2};  
    proof.T2 = ECPointVectorMul(vec_A, vec_a); //pp.g * tau2 + pp.h * t2; mul(tau2, pp.g, t2, pp.h);    

    // Eq (56) -- compute the challenge x
    transcript_str += proof.T1.ToByteString() + proof.T2.ToByteString(); 
    BigInt x = Hash::StringToBigInt(transcript_str); 

    BigInt x_square = x.ModSquare(order);   

    // compute the value of l(x) and r(x) at point x
    vec_zz_temp = BigIntVectorModScalar(poly_ll1, x, BigInt(order));
    std::vector<BigInt> llx = BigIntVectorModAdd(poly_ll0, vec_zz_temp, BigInt(order));

    vec_zz_temp = BigIntVectorModScalar(poly_rr1, x, BigInt(order)); 
    std::vector<BigInt> rrx = BigIntVectorModAdd(poly_rr0, vec_zz_temp, BigInt(order)); 

    proof.tx = BigIntVectorModInnerProduct(llx, rrx, BigInt(order));  // Eq (60)  
 
    // compute taux
    proof.taux = (tau1 * x + tau2 * x_square) % order; //proof.taux = tau2 * x_square + tau1 * x; 
   
    // compute proof.mu = (alpha + rho*x) %q;  Eq (62)
    proof.mu = (alpha + rho * x) % order; 

    BigInt ktau = GenRandomBigIntLessThan(order);
    
    proof.At = pp.g * (-bn_2 * consistency_random.kb) + pp.h * (ktau); // proof.At = g^(-2 * kb) h^ktau

    BigInt w_exp_m = w.ModExp(m,order); // w_exp_m =w^m
    proof.stau = (ktau + (c * w_exp_m * proof.taux) % order) % order; // proof.stau = ktau + c * w^m * taux
  
    // transmit llx and rrx via inner product proof

    InnerProduct::PP ip_pp = InnerProduct::Setup(LEN, false); 
    ip_pp.vec_g.resize(LEN); 
    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+LEN, ip_pp.vec_g.begin()); // ip_pp.vec_g = pp.vec_g

    ip_pp.vec_h.resize(LEN); 
    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+LEN, ip_pp.vec_h.begin()); 
    ip_pp.vec_h = ECPointVectorProduct(ip_pp.vec_h, vec_y_inverse_power);  // ip_pp.vec_h = vec_h_new  

    transcript_str += x.ToByteString();  
    BigInt e = Hash::StringToBigInt(transcript_str);   

    InnerProduct::Witness ip_witness;
    ip_witness.vec_a = llx; // ip_witness.vec_a = llx
    ip_witness.vec_b = rrx; // ip_witness.vec_b = rrx

    InnerProduct::Instance ip_instance;
    ip_pp.u = pp.u * e; //ip_pp.u = u^e 

    vec_A.resize(2*LEN+1); 
    std::copy(ip_pp.vec_g.begin(), ip_pp.vec_g.end(), vec_A.begin()); 
    std::copy(ip_pp.vec_h.begin(), ip_pp.vec_h.end(), vec_A.begin()+LEN); 
    vec_A[2*LEN] = ip_pp.u;

    vec_a.resize(2*LEN+1); 
    std::copy(ip_witness.vec_a.begin(), ip_witness.vec_a.end(), vec_a.begin()); 
    std::copy(ip_witness.vec_b.begin(), ip_witness.vec_b.end(), vec_a.begin()+LEN); 
    vec_a[2*LEN] = proof.tx; 

    ip_instance.P = ECPointVectorMul(vec_A, vec_a);  
    
    std::cout << "begin to prove inner product" << std::endl;
 
    InnerProduct::Prove(ip_pp, ip_instance, ip_witness, transcript_str, proof.ip_proof); 

    #ifdef DEBUG
        std::cout << "Sigma Bullet Proof Generation Succeeds >>>" << std::endl; 
    #endif
}

bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof, ManyOutOfMany::Proof &many_out_of_many_proof)
{
    #ifdef DEBUG
        std::cout << "begin to check the proof" << std::endl; 
    #endif

    bool V1, V2, Validity; // variables for checking results

    transcript_str = "";
    transcript_str += many_out_of_many_proof.proof_commitment_A.ToByteString();
    transcript_str += many_out_of_many_proof.proof_commitment_B.ToByteString();
    BigInt v = Hash::StringToBigInt(transcript_str);
    size_t m = many_out_of_many_proof.proof_vec_lower_cipher_balance_left.size(); // m = log N
    for(size_t i = 0; i < m; i++)
    {
        transcript_str += many_out_of_many_proof.proof_vec_lower_cipher_balance_left[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_cipher_balance_right[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_cipher_transfer_left[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_lower_cipher_transfer_right[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_pk[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_g[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_opposite_cipher[i].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_lower_opposite_cipher_g[i].ToByteString();
    }

    BigInt w = Hash::StringToBigInt(transcript_str);

    for(size_t k = 0; k < m; k++)
    {
        transcript_str += many_out_of_many_proof.proof_vec_eval_f0[k].ToByteString();
        transcript_str += many_out_of_many_proof.proof_vec_eval_f1[k].ToByteString();
    }
    transcript_str += many_out_of_many_proof.proof_Za.ToByteString();
    BigInt z = Hash::StringToBigInt(transcript_str); // //recover the challenge y
    transcript_str += many_out_of_many_proof.proof_Ay_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_AD_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab0_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ab1_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Ax_re_encryption.ToByteString();
    transcript_str += many_out_of_many_proof.proof_Au.ToByteString();

    BigInt c = Hash::StringToBigInt(transcript_str);
    transcript_str += proof.A.ToByteString();
    transcript_str += proof.S.ToByteString(); 
    transcript_str += z.ToByteString(); 
    BigInt y = Hash::StringToBigInt(transcript_str);  //recover the challenge y
    BigInt y_inverse = y.ModInverse(order);  
    BigInt z_minus = z.ModNegate(order); 
    BigInt z_square = z.ModSquare(order);
    BigInt z_cubic = (z * z_square) % order; 

    transcript_str += proof.T1.ToByteString() + proof.T2.ToByteString(); 
    BigInt x = Hash::StringToBigInt(transcript_str); 
    BigInt x_square = x.ModSquare(order);  // x_square = (x * x) % q;  //recover the challenge x from \pi

    transcript_str += x.ToByteString(); 
    BigInt e = Hash::StringToBigInt(transcript_str);  // play the role of x_u
    size_t n = 2;// instance.C.size();
    size_t LEN = pp.RANGE_LEN * n; // l = nm 
    std::vector<BigInt> vec_1_power(LEN, bn_1); // vec_unary = 1^nm
    std::vector<BigInt> vec_short_1_power(pp.RANGE_LEN, bn_1); 
    std::vector<BigInt> vec_2_power = GenBigIntPowerVector(LEN, bn_2);
    std::vector<BigInt> vec_short_2_power = GenBigIntPowerVector(pp.RANGE_LEN, bn_2);  
    std::vector<BigInt> vec_y_power = GenBigIntPowerVector(LEN, y); 

    std::vector<BigInt> vec_adjust_z_power(n+1); // generate z^{j+2} j \in [n]
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= n; j++)
    {
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; 
    }  

    // compute sum_{j=1^m} z^{j+2}
    BigInt sum_z = bn_0; 
    for (auto j = 1; j <= n; j++)
    {
        sum_z += vec_adjust_z_power[j]; 
    }
    sum_z = (sum_z * z) % order;  

    // compute delta_yz (pp. 21)    
    BigInt bn_temp1 = BigIntVectorModInnerProduct(vec_1_power, vec_y_power, BigInt(order)); 
    BigInt bn_temp2 = BigIntVectorModInnerProduct(vec_short_1_power, vec_short_2_power, BigInt(order)); 
    
    BigInt bn_c0 = z.ModSub(z_square, order); // z-z^2
    bn_temp1 = bn_c0 * bn_temp1; 
    bn_temp2 = sum_z * bn_temp2; 
  
    BigInt delta_yz = bn_temp1.ModSub(bn_temp2, order);  //Eq (39) also see page 21

    //begin sigma-bullet-verify
    BigInt w_exp_m = w.ModExp(m,order); // w_exp_m = w ^m
    BigInt w_exp_m_times_c = w_exp_m * c % order; // w_exp_m_times_c = w^m * c
    BigInt left_exp_4_g = (w_exp_m_times_c * proof.tx) % order; // left_exp_4_g = w^m * c * tx
    ECPoint LEFT = pp.g * left_exp_4_g + pp.h * proof.stau; // LEFT = g^{w^m * c * tx} h^{s_tau}
    
    BigInt right_exp_4_g = (w_exp_m_times_c * delta_yz) % order; // right_exp_4_g = w^m * c * {delta_yz}
    
    BigInt Sb = (many_out_of_many_proof.proof_Sb0 + many_out_of_many_proof.proof_Sb1) % order;
 
    // RIGHT = g^{w^m * c * {delta_yz}} g^{Sb} At {T1 * x + T2 * {x^2}}^{ w^m * c}                                                                                                     {T1 * x + }
    ECPoint RIGHT = pp.g * right_exp_4_g + pp.g * (Sb) + proof.At + (proof.T1 * x 
                                         + proof.T2 * x_square) * w_exp_m_times_c; 

    // the intermediate variables used to compute the right value
    std::vector<ECPoint> vec_A; 
    std::vector<BigInt> vec_a;

    //this is replace with a sigma protocol
    V1 = (LEFT == RIGHT);
    #ifdef DEBUG
        std::cout << std::boolalpha << "Condition 1 (Aggregating Log Size BulletProof) = " << V1 << std::endl; 
    #endif

    //check Eq (66,67,68) using Inner Product Argument
    InnerProduct::PP ip_pp = InnerProduct::Setup(LEN, false); 

    ip_pp.vec_g.resize(LEN); 
    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+LEN, ip_pp.vec_g.begin()); // ip_pp.vec_g = pp.vec_g

    ip_pp.vec_h.resize(LEN); 
    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+LEN, ip_pp.vec_h.begin()); 
    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(LEN, y_inverse); // y^nm
    ip_pp.vec_h = ECPointVectorProduct(ip_pp.vec_h, vec_y_inverse_power);  // ip_pp.vec_h = vec_h_new  

    //InnerProduct_Proof ip_proof = proof.ip_proof;
    InnerProduct::Instance ip_instance;
    ip_pp.u = pp.u * e; // u = u^e 
    
    vec_A.resize(2*ip_pp.VECTOR_LEN+4); 
    std::copy(ip_pp.vec_g.begin(), ip_pp.vec_g.end(), vec_A.begin()); 
    std::copy(ip_pp.vec_h.begin(), ip_pp.vec_h.end(), vec_A.begin()+ip_pp.VECTOR_LEN);

    vec_A[2*ip_pp.VECTOR_LEN] = proof.A; 
    vec_A[2*ip_pp.VECTOR_LEN+1] = proof.S; 
    vec_A[2*ip_pp.VECTOR_LEN+2] = pp.h; 
    vec_A[2*ip_pp.VECTOR_LEN+3] = ip_pp.u; 

    vec_a.resize(2*ip_pp.VECTOR_LEN+4);
    
    std::vector<BigInt> vec_z_minus_unary(LEN, z_minus); 
    std::move(vec_z_minus_unary.begin(), vec_z_minus_unary.end(), vec_a.begin()); 

    std::vector<BigInt> vec_rr = BigIntVectorModScalar(vec_y_power, z, BigInt(order)); // z y^nm
    std::vector<BigInt> temp_vec_zz; 
    for(auto j = 1; j <= n; j++)
    {
        temp_vec_zz = BigIntVectorModScalar(vec_2_power, vec_adjust_z_power[j], BigInt(order)); 
        for(auto i = 0; i < pp.RANGE_LEN; i++)
        {
            vec_rr[(j-1)*pp.RANGE_LEN+i] = (vec_rr[(j-1)*pp.RANGE_LEN+i] + temp_vec_zz[i]) % order;            
        }
    }
    std::move(vec_rr.begin(), vec_rr.end(), vec_a.begin()+ip_pp.VECTOR_LEN); 
     
    vec_a[2*ip_pp.VECTOR_LEN] = bn_1; 
    vec_a[2*ip_pp.VECTOR_LEN+1] = x; 
    vec_a[2*ip_pp.VECTOR_LEN+2] = -proof.mu; 
    vec_a[2*ip_pp.VECTOR_LEN+3] = proof.tx; 


    ip_instance.P = ECPointVectorMul(vec_A, vec_a);  // set P_new = A + S^x + h^{-mu} u^tx  

    V2 = InnerProduct::FastVerify(ip_pp, ip_instance, transcript_str, proof.ip_proof); 
   
    Validity = V1 && V2;     
    #ifdef DEBUG
    if (Validity)
    { 
        std::cout<< "log size Sigma BulletProof accepts >>>" << std::endl; 
    }
    else
    {
        std::cout<< "log size Sigma BulletProof rejects >>>" << std::endl; 
    }
    #endif

    return Validity; 
}





}
#endif