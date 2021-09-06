/***********************************************************************************
this hpp implements aggregated logarithmic size Bulletproofs  
***********************************************************************************/
#ifndef BULLET_PROOF_HPP_
#define BULLET_PROOF_HPP_
#include "innerproduct_proof.hpp" 

// define the structure of Bulletproofs
struct Bullet_PP
{
    size_t RANGE_LEN; 
    size_t LOG_RANGE_LEN; 
    size_t AGG_NUM; // number of sub-argument (for now, we require m to be the power of 2)

    ECPoint g, h;
    ECPoint u; // used for inside innerproduct statement
    std::vector<ECPoint> vec_g, vec_h; // the pp of innerproduct part    
};

struct Bullet_Instance
{
    std::vector<ECPoint> C;  // Ci = g^ri h^vi: length = AGG_NUM
}; 

struct Bullet_Witness
{
    std::vector<BigInt> r; // length = AGG_NUM
    std::vector<BigInt> v; 
}; 

struct Bullet_Proof
{
    ECPoint A, S, T1, T2;  
    BigInt taux, mu, tx; 
    InnerProduct_Proof ip_proof;    
};

/* generate a^n = (a^0, a^1, a^2, ..., a^{n-1}) */ 
void GenBigIntPowerVector(std::vector<BigInt> &result, const BigInt &a)
{
    
    result[0] = BigInt(bn_1); 
    for (auto i = 1; i < result.size(); i++)
    {
        result[i] = (result[i-1] * a) % order; // result[i] = result[i-1]*a % order
    }
}

void Bullet_Print_Proof(Bullet_Proof &proof)
{
    proof.A.Print("proof.A"); 
    proof.S.Print("proof.S"); 
    proof.T1.Print("proof.T1");  
    proof.T2.Print("proof.T2");  

    proof.taux.Print("proof.taux"); 
    proof.mu.Print("proof.mu"); 
    proof.tx.Print("proof.tx"); 

    InnerProduct_Print_Proof(proof.ip_proof); 
}

void Bullet_Serialize_Proof(Bullet_Proof &proof, std::ofstream &fout)
{
    fout << proof.A << proof.S << proof.T1 << proof.T2;
    fout << proof.taux << proof.mu << proof.tx; 
    InnerProduct_Serialize_Proof(proof.ip_proof, fout); 
}

void Bullet_Deserialize_Proof(Bullet_Proof &proof, std::ifstream &fin)
{
    fin >> proof.A >> proof.S >> proof.T1 >> proof.T2;
    fin >> proof.taux >> proof.mu >> proof.tx; 
    InnerProduct_Deserialize_Proof(proof.ip_proof, fin); 
}


void Bullet_Setup(Bullet_PP &pp, size_t &RANGE_LEN, size_t &AGG_NUM)
{
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = log2(RANGE_LEN); 
    pp.AGG_NUM = AGG_NUM; 
 
    pp.g = generator; 
    pp.h = HashToPoint(ECPointToByteString(pp.g)); 
    pp.u = GenRandomGenerator();

    pp.vec_g.resize(RANGE_LEN*AGG_NUM); 
    pp.vec_h.resize(RANGE_LEN*AGG_NUM);  

    GenRandomECPointVector(pp.vec_g);
    GenRandomECPointVector(pp.vec_h);
    //cout << "Bulletproof setup finished" << endl; 
}


// statement C = g^r h^v and v \in [0, 2^n-1]
void Bullet_Prove(Bullet_PP &pp, Bullet_Instance &instance, Bullet_Witness &witness, 
                  std::string &transcript_str, Bullet_Proof &proof)
{ 
    //Print_ECPointVector(pp.vec_g, "pp.vec_g"); 
    auto start_time = std::chrono::steady_clock::now(); 
    for (auto i = 0; i < instance.C.size(); i++){
        transcript_str += ECPointToByteString(instance.C[i]); 
    }

    size_t l = pp.RANGE_LEN * pp.AGG_NUM; // l = mn

    std::vector<BigInt> vec_aL(l);  
    std::vector<BigInt> vec_aR(l);
 
    std::vector<BigInt> vec_1_power(l, bn_1); // vec_unary = 1^nm

    for (auto i = 0; i < pp.AGG_NUM; i++)
    {
        for(auto j = 0; j < pp.RANGE_LEN; j++)
        {
            if(witness.v[i].GetTheNthBit(j) == 1){
                vec_aL[i*pp.RANGE_LEN + j] = bn_1;  
            }
            else{
                vec_aL[i*pp.RANGE_LEN + j] = bn_0; 
            } 
        }
    }

    BigIntVector_ModSub(vec_aR, vec_aL, vec_1_power); // Eq (42) -- aR = aL - 1^n

    // prepare vec_A and vec_a for multi-exponention (used hereafter)
    std::vector<ECPoint> vec_A; 
    std::vector<BigInt> vec_a; 

    // Eq (44) -- compute A = H^alpha g^aL h^aR (commitment to aL and aR)
    BigInt alpha = GenRandomBigIntLessThan(order); 

    vec_A.emplace_back(pp.h); 
    vec_A.insert(vec_A.end(), pp.vec_g.begin(), pp.vec_g.end()); 
    vec_A.insert(vec_A.end(), pp.vec_h.begin(), pp.vec_h.end()); 

    vec_a.emplace_back(alpha); 
    vec_a.insert(vec_a.end(), vec_aL.begin(), vec_aL.end()); 
    vec_a.insert(vec_a.end(), vec_aR.begin(), vec_aR.end()); 

    proof.A = ECPointVector_Mul(vec_A, vec_a); // Eq (44) 


    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    std::vector<BigInt> vec_sL(l);
    GenRandomBigIntVectorLessThan(vec_sL, order); 

    std::vector<BigInt> vec_sR(l);
    GenRandomBigIntVectorLessThan(vec_sR, order); 
    
    // Eq (47) compute S = H^alpha g^aL h^aR (commitment to sL and sR)
    BigInt rho = GenRandomBigIntLessThan(order); 

    vec_a.clear(); 
    vec_a.emplace_back(rho); 
    vec_a.insert(vec_a.end(), vec_sL.begin(), vec_sL.end()); 
    vec_a.insert(vec_a.end(), vec_sR.begin(), vec_sR.end()); 

    proof.S = ECPointVector_Mul(vec_A, vec_a); // Eq (47) 

    // Eq (49, 50) compute y and z
    transcript_str += ECPointToByteString(proof.A); 
    BigInt y = HashToBigInt(transcript_str);

    BigInt y_inverse = y.ModInverse(order);
     
    std::vector<BigInt> vec_y_inverse_power(l); 

    GenBigIntPowerVector(vec_y_inverse_power, y_inverse); // y^{-i+1}

    transcript_str += ECPointToByteString(proof.S); 
    BigInt z = HashToBigInt(transcript_str);

    BigInt z_square = z.ModSquare(order);
    BigInt z_cubic = (z * z_square) % order;
    
    std::vector<BigInt> vec_adjust_z_power(pp.AGG_NUM+1); // generate z^{j+1} j \in [n] 
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        //vec_adjust_z_power[j] = pow(z, j+1, q); description below Eq (71)
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; 
    }  

    // prepare the vector polynomials
    
    // compute l(X) Eq (70)
    std::vector<BigInt> vec_z_unary(l, z); // z \cdot 1^nm

    std::vector<BigInt> poly_ll0(l); 
    BigIntVector_ModSub(poly_ll0, vec_aL, vec_z_unary);  
    std::vector<BigInt> poly_ll1(l); 
    poly_ll1.assign(vec_sL.begin(), vec_sL.end()); 

    // compute r(X)     
    std::vector<BigInt> poly_rr0(l);  

    std::vector<BigInt> vec_y_power(l);  
    GenBigIntPowerVector(vec_y_power, y); // y^nm

    std::vector<BigInt> vec_zz_temp(l);  
    BigIntVector_ModAdd(vec_zz_temp, vec_z_unary, vec_aR); // vec_t = aR + z1^nm
    BigIntVector_ModProduct(poly_rr0, vec_y_power, vec_zz_temp); // y^nm(aR + z1^nm)
    
    std::vector<BigInt> vec_short_2_power(pp.RANGE_LEN);  
    GenBigIntPowerVector(vec_short_2_power, bn_2); // 2^n

    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        for (auto i = 0; i < (j-1)*pp.RANGE_LEN; i++) 
            vec_zz_temp[i] = BigInt(bn_0); 
        for (auto i = 0; i < pp.RANGE_LEN; i++) 
            vec_zz_temp[(j-1)*pp.RANGE_LEN+i] = vec_short_2_power[i]; 
        for (auto i = 0; i < (pp.AGG_NUM-j)*pp.RANGE_LEN; i++) 
            vec_zz_temp[j*pp.RANGE_LEN+i] = BigInt(bn_0);

        BigIntVector_ModScalar(vec_zz_temp, vec_zz_temp, vec_adjust_z_power[j]); 
        BigIntVector_ModAdd(poly_rr0, poly_rr0, vec_zz_temp);  
    }
    std::vector<BigInt> poly_rr1(l);  
    BigIntVector_ModProduct(poly_rr1, vec_y_power, vec_sR); //y^nsR X

    // compute t(X) 
    BigInt t0 = BigIntVector_ModInnerProduct(poly_ll0, poly_rr0); 
    BigInt bn_temp1 = BigIntVector_ModInnerProduct(poly_ll1, poly_rr0); 
    BigInt bn_temp2 = BigIntVector_ModInnerProduct(poly_ll0, poly_rr1);
    BigInt t1 = (bn_temp1 + bn_temp2) % order;  
  
    BigInt t2 = BigIntVector_ModInnerProduct(poly_ll1, poly_rr1); 

    // Eq (53) -- commit to t1, t2
    // P picks tau1 and tau2
    BigInt tau1 = GenRandomBigIntLessThan(order); 
    BigInt tau2 = GenRandomBigIntLessThan(order); 

    vec_A.clear(); vec_A = {pp.g, pp.h};
    
    vec_a.clear(); vec_a = {tau1, t1};  
    proof.T1 = ECPointVector_Mul(vec_A, vec_a); //pp.g * tau1 + pp.h * t1; mul(tau1, pp.g, t1, pp.h);
    
    vec_a.clear(); vec_a = {tau2, t2};  
    proof.T2 = ECPointVector_Mul(vec_A, vec_a); //pp.g * tau2 + pp.h * t2; mul(tau2, pp.g, t2, pp.h);    

    // Eq (56) -- compute the challenge x
    transcript_str += ECPointToByteString(proof.T1) + ECPointToByteString(proof.T2); 
    BigInt x = HashToBigInt(transcript_str); 

    BigInt x_square = x.ModSquare(order);   

    // compute the value of l(x) and r(x) at point x
    std::vector<BigInt> llx(l); 
    BigIntVector_ModScalar(vec_zz_temp, poly_ll1, x);
    BigIntVector_ModAdd(llx, poly_ll0, vec_zz_temp);

    std::vector<BigInt> rrx(l); 
    BigIntVector_ModScalar(vec_zz_temp, poly_rr1, x); 
    BigIntVector_ModAdd(rrx, poly_rr0, vec_zz_temp); 

    proof.tx = BigIntVector_ModInnerProduct(llx, rrx);  // Eq (60)  
 
    // compute taux
    proof.taux = (tau1 * x + tau2 * x_square) % order; //proof.taux = tau2*x_square + tau1*x; 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        proof.taux = (proof.taux + vec_adjust_z_power[j] * witness.r[j-1]) % order; 
    }

    // compute proof.mu = (alpha + rho*x) %q;  Eq (62)
    proof.mu = (alpha + rho * x) % order; 
    
    // transmit llx and rrx via inner product proof
    std::vector<ECPoint> vec_h_new(l);  
    ECPointVector_Product(vec_h_new, pp.vec_h, vec_y_inverse_power); 

    InnerProduct_PP ip_pp; 
    InnerProduct_Setup(ip_pp, pp.RANGE_LEN*pp.AGG_NUM, false); 
    ip_pp.vec_g.assign(pp.vec_g.begin(), pp.vec_g.end()); // ip_pp.vec_g = pp.vec_g
    ip_pp.vec_h.assign(vec_h_new.begin(), vec_h_new.end());  // ip_pp.vec_h = vec_h_new  

    transcript_str += BigIntToByteString(x);  
    BigInt e = HashToBigInt(transcript_str);   

    InnerProduct_Witness ip_witness;
    ip_witness.vec_a.resize(l);
    ip_witness.vec_b.resize(l);  
    ip_witness.vec_a.assign(llx.begin(), llx.end()); // ip_witness.vec_a = llx
    ip_witness.vec_b.assign(rrx.begin(), rrx.end()); // ip_witness.vec_b = rrx

    InnerProduct_Instance ip_instance;
    ip_pp.u = pp.u * e; //ip_pp.u = u^e 

    vec_A.clear(); vec_a.clear();

    vec_A.emplace_back(ip_pp.u); 
    vec_A.insert(vec_A.end(), ip_pp.vec_g.begin(), ip_pp.vec_g.end()); 
    vec_A.insert(vec_A.end(), ip_pp.vec_h.begin(), ip_pp.vec_h.end()); 

    vec_a.emplace_back(proof.tx); 
    vec_a.insert(vec_a.end(), ip_witness.vec_a.begin(), ip_witness.vec_a.end()); 
    vec_a.insert(vec_a.end(), ip_witness.vec_b.begin(), ip_witness.vec_b.end()); 

    ip_instance.P = ECPointVector_Mul(vec_A, vec_a);  

    transcript_str += ECPointToByteString(ip_instance.P);  
 
    InnerProduct_Prove(ip_pp, ip_instance, ip_witness, transcript_str, proof.ip_proof); 

    #ifdef DEBUG
        std::cout << "Bullet Proof Generation Succeeds >>>" << std::endl; 
    #endif
}

bool Bullet_Verify(Bullet_PP &pp, Bullet_Instance &instance, std::string &transcript_str, Bullet_Proof &proof)
{
    #ifdef DEBUG
        std::cout << "begin to check the proof" << std::endl; 
    #endif

    for (auto i = 0; i < instance.C.size(); i++){
        transcript_str += ECPointToByteString(instance.C[i]); 
    }

    bool V1, V2, Validity; // variables for checking results

    transcript_str += ECPointToByteString(proof.A); 
    BigInt y = HashToBigInt(transcript_str);  //recover the challenge y
    BigInt y_inverse = y.ModInverse(order); 

    
    transcript_str += ECPointToByteString(proof.S); 
    BigInt z = HashToBigInt(transcript_str); // recover the challenge z

    BigInt z_minus = z.ModNegate(order); 
    BigInt z_square = z.ModSquare(order); // (z*z)%q; 
    BigInt z_cubic = (z * z_square) % order; 

    transcript_str += ECPointToByteString(proof.T1) + ECPointToByteString(proof.T2); 
    BigInt x = HashToBigInt(transcript_str); 
    BigInt x_square = x.ModSquare(order);  // (x*x)%q;  //recover the challenge x from PI

    transcript_str += BigIntToByteString(x); 
    BigInt e = HashToBigInt(transcript_str);  // ???

    size_t l = pp.RANGE_LEN * pp.AGG_NUM; 

    std::vector<BigInt> vec_1_power(l, bn_1); // vec_unary = 1^nm
    
    std::vector<BigInt> vec_short_1_power(pp.RANGE_LEN, bn_1); 

    std::vector<BigInt> vec_2_power(l); 
    GenBigIntPowerVector(vec_2_power, bn_2);

    std::vector<BigInt> vec_short_2_power(pp.RANGE_LEN);
    GenBigIntPowerVector(vec_short_2_power, bn_2);  

    std::vector<BigInt> vec_y_power(l); 
    GenBigIntPowerVector(vec_y_power, y); 

    std::vector<BigInt> vec_adjust_z_power(pp.AGG_NUM+1); // generate z^{j+2} j \in [n]
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; 
    }  

    // compute sum_{j=1^m} z^{j+2}
    BigInt sum_z = bn_0; 
    for (auto j = 1; j <= pp.AGG_NUM; j++)
    {
        sum_z += vec_adjust_z_power[j]; 
    }
    sum_z = (sum_z * z) % order;  

    // compute delta_yz (pp. 21)    
    BigInt bn_temp1 = BigIntVector_ModInnerProduct(vec_1_power, vec_y_power); 
    BigInt bn_temp2 = BigIntVector_ModInnerProduct(vec_short_1_power, vec_short_2_power); 

    BigInt bn_c0 = z.ModSub(z_square, order); // z-z^2
    bn_temp1 = bn_c0 * bn_temp1; 
    bn_temp2 = sum_z * bn_temp2; 
  
    BigInt delta_yz = bn_temp1.ModSub(bn_temp2, order);  //Eq (39) also see page 21


    // check Eq (72)  
    ECPoint LEFT = pp.g * proof.taux + pp.h * proof.tx;  // LEFT = g^{\taux} h^\hat{t}

    // the intermediate variables used to compute the right value
    std::vector<ECPoint> vec_A; 
    std::vector<BigInt> vec_a;
    vec_A.resize(pp.AGG_NUM + 3); 
    vec_a.resize(pp.AGG_NUM + 3);

    copy(instance.C.begin(), instance.C.end(), vec_A.begin()); 
    copy(vec_adjust_z_power.begin()+1, vec_adjust_z_power.end(), vec_a.begin()); 

    vec_A[pp.AGG_NUM] = pp.h, vec_A[pp.AGG_NUM+1] = proof.T1, vec_A[pp.AGG_NUM+2] = proof.T2;
    vec_a[pp.AGG_NUM] = delta_yz, vec_a[pp.AGG_NUM+1] = x, vec_a[pp.AGG_NUM+2] = x_square;  

    ECPoint RIGHT = ECPointVector_Mul(vec_A, vec_a);  // RIGHT = V^{z^2} h^{\delta_yz} T_1^x T_2^{x^2} 

    V1 = (LEFT == RIGHT); 
    #ifdef DEBUG
        std::cout << std::boolalpha << "Condition 1 (Aggregating Log Size BulletProof) = " << V1 << std::endl; 
    #endif

    std::vector<BigInt> vec_y_inverse_power(l); 
    GenBigIntPowerVector(vec_y_inverse_power, y_inverse); // y^nm
    std::vector<ECPoint> vec_h_new(l); 
    ECPointVector_Product(vec_h_new, pp.vec_h, vec_y_inverse_power); 

    //check Eq (66,67,68) using Inner Product Argument
    InnerProduct_PP ip_pp; 
    InnerProduct_Setup(ip_pp, l, false); 
    ip_pp.vec_g.assign(pp.vec_g.begin(), pp.vec_g.end());
    ip_pp.vec_h.assign(vec_h_new.begin(), vec_h_new.end());  

    //InnerProduct_Proof ip_proof = proof.ip_proof;
    InnerProduct_Instance ip_instance;
    ip_pp.u = pp.u * e; // u = u^e 
    
    vec_A.clear(); vec_a.clear(); 
    vec_A.emplace_back(proof.A); vec_A.emplace_back(proof.S); 
    vec_a.emplace_back(bn_1); vec_a.emplace_back(x); // LEFT = A+S^x

    std::vector<BigInt> vec_z_minus_unary(l, z_minus); 

    vec_A.insert(vec_A.end(), ip_pp.vec_g.begin(), ip_pp.vec_g.end()); 
    vec_a.insert(vec_a.end(), vec_z_minus_unary.begin(), vec_z_minus_unary.end()); // LEFT += g^{-1 z^n} 
      
    std::vector<BigInt> vec_rr(l);  
    BigIntVector_ModScalar(vec_rr, vec_y_power, z); // z y^nm

    std::vector<BigInt> temp_vec_zz(l); 
    for(auto j = 1; j <= pp.AGG_NUM; j++)
    {
        BigIntVector_ModScalar(temp_vec_zz, vec_2_power, vec_adjust_z_power[j]); 
        for(auto i = 0; i < pp.RANGE_LEN; i++)
        {
            vec_rr[(j-1)*pp.RANGE_LEN+i] = (vec_rr[(j-1)*pp.RANGE_LEN+i] + temp_vec_zz[i]) % order;            
        }
    }

    vec_A.insert(vec_A.end(), ip_pp.vec_h.begin(), ip_pp.vec_h.end()); 
    vec_a.insert(vec_a.end(), vec_rr.begin(), vec_rr.end()); 

    proof.mu = proof.mu.ModNegate(order); 
    vec_A.emplace_back(pp.h); vec_A.emplace_back(ip_pp.u); 
    vec_a.emplace_back(proof.mu); vec_a.emplace_back(proof.tx); 
    ip_instance.P = ECPointVector_Mul(vec_A, vec_a);  // set P_new = P h^{-u} U^<l, r>   

    transcript_str += ECPointToByteString(ip_instance.P); 
    V2 = InnerProduct_Verify(ip_pp, ip_instance, transcript_str, proof.ip_proof); 
    #ifdef DEBUG
        std::cout << std::boolalpha << "Condition 2 (Aggregating Log Size BulletProof) = " << V2 << std::endl; 
    #endif

    Validity = V1 && V2;     
    #ifdef DEBUG
    if (Validity){ 
        std::cout<< "log size BulletProof accepts..." << std::endl; 
    }
    else{
        std::cout<< "log size BulletProof rejects..." << std::endl; 
    }
    #endif

    return Validity; 
}

#endif
