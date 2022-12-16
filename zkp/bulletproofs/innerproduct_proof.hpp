/***********************************************************************************
this hpp implements the inner product proof system  
***********************************************************************************/
#ifndef IP_PROOF_HPP
#define IP_PROOF_HPP

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"

namespace InnerProduct{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define the structure of InnerProduct Proof
struct PP
{
    size_t VECTOR_LEN;      // denotes the size of witness (witness is upto l = 2^VECTOR_LEN)
    size_t LOG_VECTOR_LEN;  // LOG_VECTOR_LEN = log(VECTOR_LEN) 
    
    // size of the vector = VECTOR_LEN
    std::vector<ECPoint> vec_g; 
    std::vector<ECPoint> vec_h; 
    ECPoint u; 
};

//P = vec_g^vec_a vec_h^vec_b u^<vec_a, vec_b>
struct Instance
{
    ECPoint P; 
};

struct Witness
{
    // size of the vector = VECTOR_LEN
    std::vector<BigInt> vec_a; 
    std::vector<BigInt> vec_b; 
};

struct Proof
{
    // size of the vector = LOG_VECTOR_LEN
    std::vector<ECPoint> vec_L; 
    std::vector<ECPoint> vec_R; 
    BigInt a; 
    BigInt b;     
};

std::ofstream &operator<<(std::ofstream &fout, const InnerProduct::Proof &proof)
{
    fout << proof.vec_L << proof.vec_R; 
    fout << proof.a << proof.b; 
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, InnerProduct::Proof &proof)
{
    fin >> proof.vec_L >> proof.vec_R; 
    fin >> proof.a >> proof.b; 
    return fin; 
}


std::string ProofToByteString(Proof &proof)
{
    std::string str;
    for(auto i = 0; i < proof.vec_L.size(); i++){
        str += proof.vec_L[i].ToByteString(); 
    } 
    for(auto i = 0; i < proof.vec_R.size(); i++){
        str += proof.vec_R[i].ToByteString(); 
    } 
    
    str += proof.a.ToByteString() + proof.b.ToByteString();
    return str;  
}


void PrintPP(PP &pp)
{
    std::cout << "vector length = " << pp.VECTOR_LEN << std::endl;   
    std::cout << "log vector length = " << pp.LOG_VECTOR_LEN << std::endl;   
    
    // size of the vector = VECTOR_LEN
    PrintECPointVector(pp.vec_g, "g"); 
    PrintECPointVector(pp.vec_h, "h"); 

    pp.u.Print("u"); 

}

void PrintWitness(Witness &witness)
{
    PrintBigIntVector(witness.vec_a, "a"); 
    PrintBigIntVector(witness.vec_b, "b"); 
}

void PrintInstance(Instance &instance)
{
    instance.P.Print("ip_instance.P"); 
}

void PrintProof(Proof &proof)
{
    PrintECPointVector(proof.vec_L, "L");
    PrintECPointVector(proof.vec_R, "R");
    proof.a.Print("proof.a"); 
    proof.b.Print("proof.b"); 
};

/* compute the jth bit of a small integer num \in [0, 2^{l-1}] (count from big endian to little endian) */ 
uint64_t GetTheNthBitofInt(uint64_t i, size_t j, size_t LEN)
{ 
    uint64_t cursor = 1 << (LEN-j-1); // set cursor = 2^{m-1} = 1||0...0---(m-1)
    if ((i&cursor) != 0) return 1;
    else return 0;  
}


/* assign left or right part of a Zn vector */ 
void AssignBigIntVector(std::vector<BigInt> &result, std::vector<BigInt> &vec_a, std::string selector)
{
    size_t LEN = vec_a.size()/2; 
    std::vector<BigInt>::iterator start_index; 
    if (selector == "left") start_index = vec_a.begin(); 
    if (selector == "right") start_index = vec_a.begin() + LEN; 

    result.assign(start_index, start_index + LEN);     
}

// assign left or right part of an ECn vector
void AssignECPointVector(std::vector<ECPoint> &result, std::vector<ECPoint> &vec_g, std::string selector)
{
    size_t LEN = vec_g.size()/2; 
    std::vector<ECPoint>::iterator start_index; 
    if (selector == "left") start_index = vec_g.begin(); 
    if (selector == "right") start_index = vec_g.begin() + LEN; 

    result.assign(start_index, start_index + LEN);    
}

/* this module is used to enable fast verification (cf pp.15) */
void ComputeVectorSS(std::vector<BigInt> &vec_s, std::vector<BigInt> &vec_x, std::vector<BigInt> &vec_x_inverse)
{
    size_t m = vec_x.size(); 
    size_t n = vec_s.size(); //int n = pow(2, m); 
    
    // compute s[0], ..., s[i-1]
    // vector<BIGNUM *> vec_s(n); 
    uint64_t flag; 
    for (auto i = 0; i < n; i++)
    {
        vec_s[i] = BigInt(bn_1); // set s[i] = 1
        for (auto j = 0; j < m; j++)
        {
            flag = GetTheNthBitofInt(i, j, m);
            if (flag == 1){
                vec_s[i] = (vec_s[i] * vec_x[j]) % order;
            } 
            else{
                vec_s[i] = (vec_s[i] * vec_x_inverse[j]) % order;
            } 
        }
    }
} 


/* (Protocol 2 on pp.15) */
PP Setup(size_t VECTOR_LEN, bool INITIAL_FLAG)
{
    PP pp;
    if(IsPowerOfTwo(VECTOR_LEN)==false){
        std::cerr << "VECTOR_LEN must be power of 2" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    pp.VECTOR_LEN = VECTOR_LEN;
    pp.LOG_VECTOR_LEN = log2(VECTOR_LEN);  

    if(INITIAL_FLAG == true){
        pp.vec_g = GenRandomECPointVector(pp.VECTOR_LEN);
        pp.vec_h = GenRandomECPointVector(pp.VECTOR_LEN);
        pp.u = GenRandomGenerator(); 
    }

    return pp;
}

/* 
    Generate an argument PI for Relation 3 on pp.13: P = g^a h^b u^<a,b> 
    transcript_str is introduced to be used as a sub-protocol 
*/
void Prove(PP pp, Instance instance, Witness witness, std::string &transcript_str, Proof &proof)
{
    if (pp.vec_g.size()!=pp.vec_h.size()) 
    {
        std::cerr << "vector size does not match!" << std::endl;
        exit(EXIT_FAILURE); 
    }

    if(IsPowerOfTwo(pp.VECTOR_LEN)==false){
        std::cerr << "VECTOR_LEN must be power of 2" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    size_t n = pp.VECTOR_LEN; // the current size of vec_G and vec_H

    // the last round
    if (n == 1)
    {
        proof.a = witness.vec_a[0];
        proof.b = witness.vec_b[0]; 
 
        #ifdef DEBUG
        std::cerr << "Inner Product Proof Generation Finishes >>>" << std::endl;
        #endif 

        return; 
    } 

    else{
        n = n/2; 
    
        // prepare the log(n)-th round message
        std::vector<BigInt> vec_aL(n), vec_aR(n), vec_bL(n), vec_bR(n);
        std::vector<ECPoint> vec_gL(n), vec_gR(n), vec_hL(n), vec_hR(n);

        // prepare aL, aR, bL, bR
        AssignBigIntVector(vec_aL, witness.vec_a, "left");
        AssignBigIntVector(vec_aR, witness.vec_a, "right");
        AssignBigIntVector(vec_bL, witness.vec_b, "left"); 
        AssignBigIntVector(vec_bR, witness.vec_b, "right");

        AssignECPointVector(vec_gL, pp.vec_g, "left"); 
        AssignECPointVector(vec_gR, pp.vec_g, "right"); 
        AssignECPointVector(vec_hL, pp.vec_h, "left"); 
        AssignECPointVector(vec_hR, pp.vec_h, "right");


        // compute cL, cR
        BigInt cL = BigIntVectorModInnerProduct(vec_aL, vec_bR, BigInt(order)); // Eq (21)        
        BigInt cR = BigIntVectorModInnerProduct(vec_aR, vec_bL, BigInt(order)); // Eq (22)

        // compute L, R
        std::vector<ECPoint> vec_A(2*n+1); 
        std::vector<BigInt> vec_a(2*n+1);

        std::copy(vec_gR.begin(), vec_gR.end(), vec_A.begin());
        std::copy(vec_hL.begin(), vec_hL.end(), vec_A.begin() + n);
        vec_A[2*n] = pp.u; 


        std::copy(vec_aL.begin(), vec_aL.end(), vec_a.begin()); 
        std::copy(vec_bR.begin(), vec_bR.end(), vec_a.begin()+n); 
        vec_a[2*n] = cL; 

        ECPoint L = ECPointVectorMul(vec_A, vec_a);  // Eq (23) 

 

        std::copy(vec_gL.begin(), vec_gL.end(), vec_A.begin());
        std::copy(vec_hR.begin(), vec_hR.end(), vec_A.begin() + n);
        vec_A[2*n] = pp.u; 


        std::copy(vec_aR.begin(), vec_aR.end(), vec_a.begin()); 
        std::copy(vec_bL.begin(), vec_bL.end(), vec_a.begin()+n); 
        vec_a[2*n] = cR; 

        ECPoint R = ECPointVectorMul(vec_A, vec_a);  // Eq (24)

        proof.vec_L.emplace_back(L); 
        proof.vec_R.emplace_back(R);  // store the n-th round L and R values

        // compute the challenge
        transcript_str += L.ToByteString() + R.ToByteString(); 
        BigInt x = Hash::StringToBigInt(transcript_str); // compute the n-th round challenge Eq (26,27)

        // x.Print(); 
        BigInt x_inverse = x.ModInverse(order);
        // generate new pp
        /*
        ** pp_sub.VECTOR_LEN = pp.VECTOR_LEN/2; 
        ** pp_sub.LOG_VECTOR_LEN = pp.LOG_VECTOR_LEN - 1;  
        */
        PP pp_sub = Setup(pp.VECTOR_LEN/2, false);

        // compute vec_g
        vec_gL = ECPointVectorScalar(vec_gL, x_inverse); 
        vec_gR = ECPointVectorScalar(vec_gR, x); 
        pp_sub.vec_g = ECPointVectorAdd(vec_gL, vec_gR); // Eq (29)

        // compute vec_h
        vec_hL = ECPointVectorScalar(vec_hL, x); 
        vec_hR = ECPointVectorScalar(vec_hR, x_inverse); 
        pp_sub.vec_h = ECPointVectorAdd(vec_hL, vec_hR); // Eq (30)

        // generate new instance
        Instance instance_sub; 
 
        pp_sub.u = pp.u; // pp_sub.u = pp.u 
 
        BigInt x_square = x.ModSquare(order); // vec_x[0] = x^2 mod q
        BigInt x_inverse_square = x_inverse.ModSquare(order); // vec_x[0] = x^2 mod q

        vec_A.clear(); 
        vec_a.clear();
        vec_A = {L, instance.P, R};  
        vec_a = {x_square, bn_1, x_inverse_square}; 

        //instance_sub.P = L * x_square + instance.P + R * x_inverse_square; 
        instance_sub.P = ECPointVectorMul(vec_A, vec_a); // Eq (31) P' = L^{x^2} P R^{x^{-2}}

        // generate new witness
        Witness witness_sub; 
    
        vec_aL = BigIntVectorModScalar(vec_aL, x, BigInt(order)); 
        vec_aR = BigIntVectorModScalar(vec_aR, x_inverse, BigInt(order)); 
        witness_sub.vec_a = BigIntVectorModAdd(vec_aL, vec_aR, BigInt(order)); // Eq (33)

        vec_bL = BigIntVectorModScalar(vec_bL, x_inverse, BigInt(order)); 
        vec_bR = BigIntVectorModScalar(vec_bR, x, BigInt(order)); 
        witness_sub.vec_b = BigIntVectorModAdd(vec_bL, vec_bR, BigInt(order)); // Eq (34)

        // recursively invoke the InnerProduct proof
        Prove(pp_sub, instance_sub, witness_sub, transcript_str, proof); 
    }
}

/* Check if PI is a valid proof for inner product statement (G1^w = H1 and G2^w = H2) */
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    if(IsPowerOfTwo(pp.VECTOR_LEN)==false){
        std::cerr << "VECTOR_LEN must be power of 2" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    bool Validity;

    // auto start_time = std::chrono::steady_clock::now(); // start to count the time
    // recover the challenge
    std::vector<BigInt> vec_x(pp.LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    std::vector<BigInt> vec_x_square(pp.LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse_square(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    
    for (auto i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {  
        transcript_str += proof.vec_L[i].ToByteString() + proof.vec_R[i].ToByteString(); 
        vec_x[i] = Hash::StringToBigInt(transcript_str); // reconstruct the challenge

        vec_x_square[i] = vec_x[i].ModSquare(order); 
        vec_x_inverse[i] = vec_x[i].ModInverse(order);  
        vec_x_inverse_square[i] = vec_x_inverse[i].ModSquare(order); 
    }

    // define the left and right side of the equation on top of pp.17 (with slight modification)
    std::vector<ECPoint> vec_A(2*pp.VECTOR_LEN+1); 
    std::vector<BigInt> vec_a(2*pp.VECTOR_LEN+1); 

    // compute left
    std::vector<BigInt> vec_s(pp.VECTOR_LEN); 
    std::vector<BigInt> vec_s_inverse(pp.VECTOR_LEN); 


    ComputeVectorSS(vec_s, vec_x, vec_x_inverse); // page 15: the s vector
    vec_s_inverse = BigIntVectorModInverse(vec_s, BigInt(order));  // the s^{-1} vector
    vec_s = BigIntVectorScalar(vec_s, proof.a); 
    vec_s_inverse = BigIntVectorScalar(vec_s_inverse, proof.b); 


    std::move(pp.vec_g.begin(), pp.vec_g.end(), vec_A.begin());
    std::move(pp.vec_h.begin(), pp.vec_h.end(), vec_A.begin()+pp.VECTOR_LEN);
    vec_A[2*pp.VECTOR_LEN] = pp.u; 

    std::move(vec_s.begin(), vec_s.end(), vec_a.begin()); // pp.vec_g, vec_s
    std::move(vec_s_inverse.begin(), vec_s_inverse.end(), vec_a.begin()+pp.VECTOR_LEN); 
    vec_a[2*pp.VECTOR_LEN] = proof.a * proof.b; // LEFT = u^{ab}

    ECPoint LEFT = ECPointVectorMul(vec_A, vec_a); 

    // compute right
    vec_A.resize(2*pp.LOG_VECTOR_LEN+1);  
    std::move(proof.vec_L.begin(), proof.vec_L.end(), vec_A.begin()); 
    std::move(proof.vec_R.begin(), proof.vec_R.end(), vec_A.begin()+pp.LOG_VECTOR_LEN); 

    vec_a.resize(2*pp.LOG_VECTOR_LEN+1);
    std::move(vec_x_square.begin(), vec_x_square.end(), vec_a.begin()); 
    std::move(vec_x_inverse_square.begin(), vec_x_inverse_square.end(), vec_a.begin()+pp.LOG_VECTOR_LEN); 

    vec_A[2*pp.LOG_VECTOR_LEN] = instance.P; 
    vec_a[2*pp.LOG_VECTOR_LEN] = bn_1; 

    ECPoint RIGHT = ECPointVectorMul(vec_A, vec_a);  

    // the equation on top of page 17
    if (LEFT == RIGHT) {
        Validity = true;
        #ifdef DEBUG 
        std::cout<< "Inner Product Proof Accept >>>" << std::endl; 
        #endif
    }
    else {
        Validity = false;
        #ifdef DEBUG
        std::cout<< "Inner Product Proof Reject >>>" << std::endl; 
        #endif
    }

    return Validity;
}



/* this module is used to enable fast verification (cf pp.15) */
std::vector<BigInt> FastComputeVectorSS(std::vector<BigInt> &vec_x_square, std::vector<BigInt> &vec_x_inverse)
{
    size_t m = vec_x_inverse.size(); 
    size_t n = pow(2, m); 
    std::vector<BigInt> vec_s(n, bn_1); 
    
    for (auto j = 0; j < m; j++){
        vec_s[0] *= vec_x_inverse[j];
    }
    vec_s[0] = vec_s[0] % order; 

    // // first compute even
    // for (auto i = 2; i < n; i+=2){
    //     int k = floor(log2(i)); // position of the first 1 of j: e.g, k of 110 = 2 
    //     vec_s[i] = (vec_s[i-(1<<k)] * vec_x_square[m-1-k]) % order; 
    // }
    // // then compute odd
    // for (auto i = 1; i < n; i+=2){ 
    //     vec_s[i] = (vec_s[i-1] * vec_x_square[m-1]) % order; 
    // } 

    /* set vec_s[0] as the starting point of iteration
    *  let z be the index we are going to compute, say 01010 or 01001
    *  we can find its "particular" precursor index y which only differs at the first 1 
    *  since we use iterative approach, such precursor always exists
    *  let the differing position be k
    *  then we have z = y * x[k]^2
    *  we can find the position of z's first 1 as floor(log2())  
    */
    for (auto i = 1; i < n; i++){
        int k = floor(log2(i)); // position of the first 1 of j: e.g, k of 110 = 2 
        vec_s[i] = (vec_s[i-(1<<k)] * vec_x_square[m-1-k]) % order; 
    }

    return vec_s;    
} 


// this is the optimized verifier algorithm
bool FastVerify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    if(IsPowerOfTwo(pp.VECTOR_LEN)==false){
        std::cerr << "VECTOR_LEN must be power of 2" << std::endl; 
        exit(EXIT_FAILURE); 
    }


    bool Validity;

    // recover the challenge
    std::vector<BigInt> vec_x(pp.LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    std::vector<BigInt> vec_x_square(pp.LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse_square(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    
    for (auto i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {  
        transcript_str += proof.vec_L[i].ToByteString() + proof.vec_R[i].ToByteString(); 
        vec_x[i] = Hash::StringToBigInt(transcript_str); // reconstruct the challenge
        //vec_x[i].Print();
        vec_x_square[i] = vec_x[i].ModSquare(order); 
        vec_x_inverse[i] = vec_x[i].ModInverse(order);  
        vec_x_inverse_square[i] = vec_x_inverse[i].ModSquare(order); 
    }

    // define the left and right side of the equation on top of pp.17 (with slight modification)
    std::vector<ECPoint> vec_A(2*pp.VECTOR_LEN+2*pp.LOG_VECTOR_LEN+1); 
    std::vector<BigInt> vec_a(2*pp.VECTOR_LEN+2*pp.LOG_VECTOR_LEN+1); 

    // compute scalar for g and h
    std::vector<BigInt> vec_s = FastComputeVectorSS(vec_x_square, vec_x_inverse); // page 15: the s vector
    std::vector<BigInt> vec_s_inverse = BigIntVectorModInverse(vec_s, BigInt(order));  // the s^{-1} vector
    vec_s = BigIntVectorScalar(vec_s, proof.a); 
    vec_s_inverse = BigIntVectorScalar(vec_s_inverse, proof.b); 

    std::move(pp.vec_g.begin(), pp.vec_g.end(), vec_A.begin()); 
    std::move(pp.vec_h.begin(), pp.vec_h.end(), vec_A.begin()+pp.VECTOR_LEN);
    std::move(proof.vec_L.begin(), proof.vec_L.end(), vec_A.begin()+2*pp.VECTOR_LEN); 
    std::move(proof.vec_R.begin(), proof.vec_R.end(), vec_A.begin()+2*pp.VECTOR_LEN+pp.LOG_VECTOR_LEN); 
    vec_A[2*pp.VECTOR_LEN+2*pp.LOG_VECTOR_LEN] = pp.u; 


    std::move(vec_s.begin(), vec_s.end(), vec_a.begin()); // pp.vec_g, vec_s
    std::move(vec_s_inverse.begin(), vec_s_inverse.end(), vec_a.begin()+pp.VECTOR_LEN); // pp.vec_h, vec_s_inverse
    std::move(vec_x_square.begin(), vec_x_square.end(), vec_a.begin()+2*pp.VECTOR_LEN); 
    std::move(vec_x_inverse_square.begin(), vec_x_inverse_square.end(), vec_a.begin()+2*pp.VECTOR_LEN+pp.LOG_VECTOR_LEN); 
    vec_a[2*pp.VECTOR_LEN+2*pp.LOG_VECTOR_LEN] = (proof.a * proof.b); // LEFT = u^{ab}   

    for(auto i = 2*pp.VECTOR_LEN; i < 2*pp.VECTOR_LEN+2*pp.LOG_VECTOR_LEN; i++){
        vec_a[i] = -vec_a[i];
    }

    
    ECPoint LEFT = ECPointVectorMul(vec_A, vec_a);  

    ECPoint RIGHT = instance.P;  

    // the equation on top of page 17
    if (LEFT==RIGHT) {
        Validity = true;
        #ifdef DEBUG 
            std::cout<< "InnerProduct Proof accepts >>>" << std::endl; 
        #endif
    }
    else {
        Validity = false;
        #ifdef DEBUG
            std::cout<< "InnerProduct Proof rejects >>>" << std::endl; 
        #endif
    }

    return Validity;
}

}

#endif