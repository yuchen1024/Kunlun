/***********************************************************************************
this hpp implements aggregated logarithmic size Bulletproofs  
***********************************************************************************/
#ifndef BULLET_PROOF_HPP_
#define BULLET_PROOF_HPP_

#include "innerproduct_proof.hpp" 

namespace Bullet{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define the structure of Bulletproofs
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
    std::vector<ECPoint> C;  // Ci = g^ri h^vi: length = AGG_NUM
}; 

struct Witness
{
    std::vector<BigInt> r; // length = AGG_NUM
    std::vector<BigInt> v; 
}; 

struct Proof
{
    ECPoint A, S, T1, T2;  
    BigInt taux, mu, tx; 
    InnerProduct::Proof ip_proof;    
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A << proof.S << proof.T1 << proof.T2;
    fout << proof.taux << proof.mu << proof.tx; 
    fout << proof.ip_proof; 
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A >> proof.S >> proof.T1 >> proof.T2;
    fin >> proof.taux >> proof.mu >> proof.tx; 
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

    InnerProduct::PrintProof(proof.ip_proof); 
}


std::string ProofToByteString(Proof &proof)
{
    std::string str;
    str += proof.A.ToByteString() + proof.S.ToByteString() + proof.T1.ToByteString() + proof.T2.ToByteString();
    str += proof.taux.ToByteString() + proof.mu.ToByteString() + proof.tx.ToByteString(); 
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

    pp.vec_g = GenRandomECPointVector(RANGE_LEN*MAX_AGG_NUM);
    pp.vec_h = GenRandomECPointVector(RANGE_LEN*MAX_AGG_NUM);

    return pp; 
}

// statement C = g^r h^v and v \in [0, 2^n-1]
void Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str, Proof &proof)
{ 
    auto start_time = std::chrono::steady_clock::now(); 

    size_t n = instance.C.size();
    size_t LEN = pp.RANGE_LEN * n; // LEN = mn

    std::vector<BigInt> vec_aL(LEN);  
    std::vector<BigInt> vec_aR(LEN);
 
    std::vector<BigInt> vec_1_power(LEN, bn_1); // vec_unary = 1^nm

    for (auto i = 0; i < n; i++)
    {
        for(auto j = 0; j < pp.RANGE_LEN; j++)
        {
            if(witness.v[i].GetTheNthBit(j) == 1){
                vec_aL[i * pp.RANGE_LEN + j] = bn_1;  
            }
            else{
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

    // Eq (49, 50) compute y and z
    transcript_str += proof.A.ToByteString(); 
    BigInt y = Hash::StringToBigInt(transcript_str);

    BigInt y_inverse = y.ModInverse(order);
     
    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(LEN, y_inverse); // y^{-i+1}

    transcript_str += proof.S.ToByteString(); 
    BigInt z = Hash::StringToBigInt(transcript_str);

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
    
    vec_a.clear(); vec_a = {tau1, t1};  
    proof.T1 = ECPointVectorMul(vec_A, vec_a); //pp.g * tau1 + pp.h * t1; mul(tau1, pp.g, t1, pp.h);
    
    vec_a.clear(); vec_a = {tau2, t2};  
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
    proof.taux = (tau1 * x + tau2 * x_square) % order; //proof.taux = tau2*x_square + tau1*x; 
    for (auto j = 1; j <= n; j++)
    {
        proof.taux = (proof.taux + vec_adjust_z_power[j] * witness.r[j-1]) % order; 
    }

    // compute proof.mu = (alpha + rho*x) %q;  Eq (62)
    proof.mu = (alpha + rho * x) % order; 
    
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
 
    InnerProduct::Prove(ip_pp, ip_instance, ip_witness, transcript_str, proof.ip_proof); 

    #ifdef DEBUG
        std::cout << "Bullet Proof Generation Succeeds >>>" << std::endl; 
    #endif
}

bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    #ifdef DEBUG
        std::cout << "begin to check the proof" << std::endl; 
    #endif

    bool V1, V2, Validity; // variables for checking results

    transcript_str += proof.A.ToByteString(); 
    BigInt y = Hash::StringToBigInt(transcript_str);  //recover the challenge y
    BigInt y_inverse = y.ModInverse(order);  
    
    transcript_str += proof.S.ToByteString(); 
    BigInt z = Hash::StringToBigInt(transcript_str); // recover the challenge z

    BigInt z_minus = z.ModNegate(order); 
    BigInt z_square = z.ModSquare(order); // (z*z)%q; 
    BigInt z_cubic = (z * z_square) % order; 

    transcript_str += proof.T1.ToByteString() + proof.T2.ToByteString(); 
    BigInt x = Hash::StringToBigInt(transcript_str); 
    BigInt x_square = x.ModSquare(order);  // (x*x)%q;  //recover the challenge x from PI

    transcript_str += x.ToByteString(); 
    BigInt e = Hash::StringToBigInt(transcript_str);  // play the role of x_u

    size_t n = instance.C.size();
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


    // check Eq (72)  
    ECPoint LEFT = pp.g * proof.taux + pp.h * proof.tx;  // LEFT = g^{\taux} h^\hat{t}

    // the intermediate variables used to compute the right value
    std::vector<ECPoint> vec_A; 
    std::vector<BigInt> vec_a;
    vec_A.resize(n + 3); 
    vec_a.resize(n + 3);

    std::copy(instance.C.begin(), instance.C.end(), vec_A.begin()); 
    std::copy(vec_adjust_z_power.begin()+1, vec_adjust_z_power.end(), vec_a.begin()); 

    vec_A[n] = pp.h, vec_A[n+1] = proof.T1, vec_A[n+2] = proof.T2;
    vec_a[n] = delta_yz, vec_a[n+1] = x, vec_a[n+2] = x_square;  

    ECPoint RIGHT = ECPointVectorMul(vec_A, vec_a);  // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2} 

    V1 = (LEFT == RIGHT); 
    #ifdef DEBUG
        std::cout << std::boolalpha << "Condition 1 (Aggregating Log Size BulletProof) = " << V1 << std::endl; 
    #endif


    // std::vector<ECPoint> vec_h_new = ThreadSafeECPointVectorProduct(pp.vec_h, vec_y_inverse_power); 

    //check Eq (66,67,68) using Inner Product Argument
    InnerProduct::PP ip_pp = InnerProduct::Setup(LEN, false); 

    ip_pp.vec_g.resize(LEN); 
    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+LEN, ip_pp.vec_g.begin()); // ip_pp.vec_g = pp.vec_g

    ip_pp.vec_h.resize(LEN); 
    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+LEN, ip_pp.vec_h.begin()); 
    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(LEN, y_inverse); // y^nm
    ip_pp.vec_h = ECPointVectorProduct(ip_pp.vec_h, vec_y_inverse_power);  // ip_pp.vec_h = vec_h_new  

    // ip_pp.vec_g = pp.vec_g;
    // ip_pp.vec_h = vec_h_new;  

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
    std::move(vec_z_minus_unary.begin(), vec_z_minus_unary.end(), vec_a.begin()); // LEFT += g^{-1 z^n} 

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
    #ifdef DEBUG
        std::cout << std::boolalpha << "Condition 2 (Aggregating Log Size BulletProof) = " << V2 << std::endl; 
    #endif

    Validity = V1 && V2;     
    #ifdef DEBUG
    if (Validity){ 
        std::cout<< "log size BulletProof accepts >>>" << std::endl; 
    }
    else{
        std::cout<< "log size BulletProof rejects >>>" << std::endl; 
    }
    #endif

    return Validity; 
}


bool FastVerify(const PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    #ifdef DEBUG
        std::cout << "begin to check the proof" << std::endl; 
    #endif

    // prepare Eq (97)
    transcript_str += proof.A.ToByteString(); 
    BigInt y = Hash::StringToBigInt(transcript_str);  //recover the challenge y
    BigInt y_inverse = y.ModInverse(order); 

    transcript_str += proof.S.ToByteString(); 
    BigInt z = Hash::StringToBigInt(transcript_str); // recover the challenge z

    BigInt z_minus = z.ModNegate(order); 
    BigInt z_square = z.ModSquare(order); // (z*z)%q; 
    BigInt z_cubic = (z * z_square) % order; 

    transcript_str += proof.T1.ToByteString() + proof.T2.ToByteString(); 
    BigInt x = Hash::StringToBigInt(transcript_str); 
    BigInt x_square = x.ModSquare(order);  // (x*x)%q;  //recover the challenge x from PI

    transcript_str += x.ToByteString(); 
    BigInt e = Hash::StringToBigInt(transcript_str);  // play the role of x_u

    size_t n = instance.C.size();
    size_t VECTOR_LEN = pp.RANGE_LEN * n; 

    if(IsPowerOfTwo(VECTOR_LEN)==false){
        std::cerr << "VECTOR_LEN must be power of 2" << std::endl; 
        exit(EXIT_FAILURE); 
    }
    size_t LOG_VECTOR_LEN = log2(VECTOR_LEN); 

    std::vector<BigInt> vec_1_power(VECTOR_LEN, bn_1); // vec_unary = 1^nm    
    std::vector<BigInt> vec_short_1_power(pp.RANGE_LEN, bn_1); 
    std::vector<BigInt> vec_2_power = GenBigIntPowerVector(VECTOR_LEN, bn_2);
    std::vector<BigInt> vec_short_2_power = GenBigIntPowerVector(pp.RANGE_LEN, bn_2);  
    std::vector<BigInt> vec_y_power = GenBigIntPowerVector(VECTOR_LEN, y); 
    std::vector<BigInt> vec_adjust_z_power(n+1); // generate z^{j+2} j \in [n]
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= n; j++)
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; 


    // compute sum_{j=1^m} z^{j+2}
    BigInt sum_z = bn_0; 
    for (auto j = 1; j <= n; j++)
        sum_z += vec_adjust_z_power[j]; 
    sum_z = (sum_z * z) % order;  

    // compute delta_yz (pp. 21)    
    BigInt bn_temp1 = BigIntVectorModInnerProduct(vec_1_power, vec_y_power, BigInt(order)); 
    BigInt bn_temp2 = BigIntVectorModInnerProduct(vec_short_1_power, vec_short_2_power, BigInt(order)); 

    BigInt bn_c0 = z.ModSub(z_square, order); // z-z^2
    bn_temp1 = bn_c0 * bn_temp1; 
    bn_temp2 = sum_z * bn_temp2; 
  
    BigInt delta_yz = bn_temp1.ModSub(bn_temp2, order);  //Eq (39) also see page 21


    // the intermediate variables used to compute the right value
    std::vector<ECPoint> vec_A(8 + n + 2*VECTOR_LEN+2*LOG_VECTOR_LEN); 
    std::vector<BigInt>  vec_a(8 + n + 2*VECTOR_LEN+2*LOG_VECTOR_LEN);
    
    size_t index_A = 0; 
    size_t index_a = 0; 

    std::copy(instance.C.begin(), instance.C.end(), vec_A.begin()); index_A += n;  
    std::copy(vec_adjust_z_power.begin()+1, vec_adjust_z_power.end(), vec_a.begin()); index_a += n;  

    vec_A[index_A]   = proof.T1; 
    vec_A[index_A+1] = proof.T2;
    vec_A[index_A+2] = pp.g; 
    vec_A[index_A+3] = pp.h;
    index_A += 4; 

    vec_a[index_a]   = x; 
    vec_a[index_a+1] = x_square; 
    vec_a[index_a+2] = -proof.taux; 
    vec_a[index_a+3] = delta_yz - proof.tx;  
    index_a += 4; 


    // pick a random challenge c (pp.29)
    BigInt c = GenRandomBigIntLessThan(order); 
    for(auto i = 0; i < index_a; i++){ 
        vec_a[i] = vec_a[i] * c; 
    }

    // continue to prepare for Eq (104)
    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(VECTOR_LEN, y_inverse); // y^nm
    std::vector<ECPoint> vec_h; 
    vec_h.resize(VECTOR_LEN); 
    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+VECTOR_LEN, vec_h.begin()); 
    vec_h = ECPointVectorProduct(vec_h, vec_y_inverse_power);  // ip_pp.vec_h = vec_h_new 

    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+VECTOR_LEN, vec_A.begin()+index_A);
    index_A += VECTOR_LEN;  
    std::copy(vec_h.begin(), vec_h.begin()+VECTOR_LEN, vec_A.begin()+index_A);
    index_A += VECTOR_LEN; 


    // compute scalar for g and h 

    // recover the challenge
    std::vector<BigInt> vec_x(LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse(LOG_VECTOR_LEN); // the vector of challenge inverse
    std::vector<BigInt> vec_x_square(LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse_square(LOG_VECTOR_LEN); // the vector of challenge inverse
    
    for (auto i = 0; i < LOG_VECTOR_LEN; i++)
    {  
        transcript_str += proof.ip_proof.vec_L[i].ToByteString() + proof.ip_proof.vec_R[i].ToByteString(); 
        vec_x[i] = Hash::StringToBigInt(transcript_str); // reconstruct the challenge

        vec_x_square[i] = vec_x[i].ModSquare(order); 
        vec_x_inverse[i] = vec_x[i].ModInverse(order);  
        vec_x_inverse_square[i] = vec_x_inverse[i].ModSquare(order); 
    }

    // compute vec_s and vec_s_inverse
    std::vector<BigInt> vec_s = InnerProduct::FastComputeVectorSS(vec_x_square, vec_x_inverse); // page 15: the s vector    
    std::vector<BigInt> vec_s_inverse = BigIntVectorModInverse(vec_s, BigInt(order));  // the s^{-1} vector
    vec_s = BigIntVectorScalar(vec_s, proof.ip_proof.a); 
    vec_s_inverse = BigIntVectorScalar(vec_s_inverse, proof.ip_proof.b); 


    std::vector<BigInt> vec_z_unary(VECTOR_LEN, z); // z \cdot 1^nm
    for(auto i = 0; i < VECTOR_LEN; i++){
        vec_a[index_a+i] = vec_s[i] + vec_z_unary[i];
    }
    index_a += VECTOR_LEN; 
 

    std::vector<BigInt> vec_rr = BigIntVectorModScalar(vec_y_power, z, BigInt(order)); // z y^nm
    std::vector<BigInt> temp_vec_zz; 
    for(auto j = 1; j <= n; j++){
        temp_vec_zz = BigIntVectorModScalar(vec_2_power, vec_adjust_z_power[j], BigInt(order)); 
        for(auto i = 0; i < pp.RANGE_LEN; i++)
            vec_rr[(j-1)*pp.RANGE_LEN+i] = (vec_rr[(j-1)*pp.RANGE_LEN+i] + temp_vec_zz[i]) % order;            
    }
    for(auto i = 0; i < VECTOR_LEN; i++){
        vec_a[index_a+i] = vec_s_inverse[i] - vec_rr[i];
    }

    index_a += VECTOR_LEN; 

    vec_A[index_A] = proof.A; 
    vec_A[index_A+1] = proof.S; 
    vec_A[index_A+2] = pp.h; 
    vec_A[index_A+3] = pp.u * e; 
    index_A += 4; 

    vec_a[index_a]   = -bn_1; 
    vec_a[index_a+1] = -x; 
    vec_a[index_a+2] = proof.mu; 
    vec_a[index_a+3] = proof.ip_proof.a * proof.ip_proof.b - proof.tx; 
    index_a += 4; 

    std::copy(proof.ip_proof.vec_L.begin(), proof.ip_proof.vec_L.end(), vec_A.begin()+index_A);
    index_A += LOG_VECTOR_LEN;  

    std::copy(proof.ip_proof.vec_R.begin(), proof.ip_proof.vec_R.end(), vec_A.begin()+index_A); 
    index_A += LOG_VECTOR_LEN; 

    for(auto i = 0; i < LOG_VECTOR_LEN; i++){
        vec_a[index_a+i] = -vec_x_square[i];
    } 
    index_a += LOG_VECTOR_LEN; 
     
    for(auto i = 0; i < LOG_VECTOR_LEN; i++){
        vec_a[index_a+i] = -vec_x_inverse_square[i];
    } 
    index_a += LOG_VECTOR_LEN; 
    
    ECPoint Result = ECPointVectorMul(vec_A, vec_a);  


    bool Validity = Result.IsAtInfinity();     
    #ifdef DEBUG
    if (Validity){ 
        std::cout<< "log size BulletProof accepts >>>" << std::endl; 
    }
    else{
        std::cout<< "log size BulletProof rejects >>>" << std::endl; 
    }
    #endif

    return Validity; 
}




}
#endif
