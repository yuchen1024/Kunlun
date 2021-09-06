/***********************************************************************************
this hpp implements the inner product proof system  
***********************************************************************************/
#ifndef IP_PROOF_HPP
#define IP_PROOF_HPP

#include "../crypto/ec_point.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define the structure of InnerProduct Proof
struct InnerProduct_PP
{
    size_t VECTOR_LEN;      // denotes the size of witness (witness is upto l = 2^VECTOR_LEN)
    size_t LOG_VECTOR_LEN;  // LOG_VECTOR_LEN = log(VECTOR_LEN) 
    
    // size of the vector = VECTOR_LEN
    std::vector<ECPoint> vec_g; 
    std::vector<ECPoint> vec_h; 
    ECPoint u; 
};

//P = vec_g^vec_a vec_h^vec_b u^<vec_a, vec_b>
struct InnerProduct_Instance
{
    ECPoint P; 
};

struct InnerProduct_Witness
{
    // size of the vector = VECTOR_LEN
    std::vector<BigInt> vec_a; 
    std::vector<BigInt> vec_b; 
};

struct InnerProduct_Proof
{
    // size of the vector = LOG_VECTOR_LEN
    std::vector<ECPoint> vec_L; 
    std::vector<ECPoint> vec_R; 
    BigInt a; 
    BigInt b;     
};

void InnerProduct_Serialize_Proof(InnerProduct_Proof &proof, std::ofstream &fout)
{
    Serialize_ECPointVector(proof.vec_L, fout);
    Serialize_ECPointVector(proof.vec_R, fout);

    fout << proof.a << proof.b; 
}

void InnerProduct_Deserialize_Proof(InnerProduct_Proof &proof, std::ifstream &fin)
{
    Deserialize_ECPointVector(proof.vec_L, fin);
    Deserialize_ECPointVector(proof.vec_R, fin);

    fin >> proof.a >> proof.b; 
}

void InnerProduct_Print_PP(InnerProduct_PP &pp)
{
    std::cout << "vector length = " << pp.VECTOR_LEN << std::endl;   
    std::cout << "log vector length = " << pp.LOG_VECTOR_LEN << std::endl;   
    
    // size of the vector = VECTOR_LEN
    Print_ECPointVector(pp.vec_g, "g"); 
    Print_ECPointVector(pp.vec_h, "h"); 

    pp.u.Print("u"); 

}

void InnerProduct_Print_Witness(InnerProduct_Witness &witness)
{
    Print_BigIntVector(witness.vec_a, "a"); 
    Print_BigIntVector(witness.vec_b, "b"); 
}

void InnerProduct_Print_Instance(InnerProduct_Instance &instance)
{
    instance.P.Print("ip_instance.P"); 
}

void InnerProduct_Print_Proof(InnerProduct_Proof &proof)
{
    Print_ECPointVector(proof.vec_L, "L");
    Print_ECPointVector(proof.vec_R, "R");
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
void InnerProduct_Setup(InnerProduct_PP &pp, size_t VECTOR_LEN, bool INITIAL_FLAG)
{
    pp.VECTOR_LEN = VECTOR_LEN;
    pp.LOG_VECTOR_LEN = log2(VECTOR_LEN);  
    pp.vec_g.resize(pp.VECTOR_LEN);
    pp.vec_h.resize(pp.VECTOR_LEN);

    if(INITIAL_FLAG == true){
        GenRandomECPointVector(pp.vec_g);
        GenRandomECPointVector(pp.vec_h);
        pp.u = GenRandomGenerator(); 
    }
}

/* 
    Generate an argument PI for Relation 3 on pp.13: P = g^a h^b u^<a,b> 
    transcript_str is introduced to be used as a sub-protocol 
*/
void InnerProduct_Prove(InnerProduct_PP pp, InnerProduct_Instance instance, InnerProduct_Witness witness,
                        std::string &transcript_str, InnerProduct_Proof &proof)
{
    if (pp.vec_g.size()!=pp.vec_h.size()) 
    {
        std::cerr << "vector size does not match!" << std::endl;
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
        BigInt cL = BigIntVector_ModInnerProduct(vec_aL, vec_bR); // Eq (21) 
        BigInt cR = BigIntVector_ModInnerProduct(vec_aR, vec_bL); // Eq (22)

        // compute L, R
        std::vector<ECPoint> vec_A; 
        std::vector<BigInt> vec_a; 


        vec_A.insert(vec_A.end(), vec_gR.begin(), vec_gR.end()); 
        vec_A.insert(vec_A.end(), vec_hL.begin(), vec_hL.end());
        vec_A.emplace_back(pp.u); 

        vec_a.insert(vec_a.end(), vec_aL.begin(), vec_aL.end()); 
        vec_a.insert(vec_a.end(), vec_bR.begin(), vec_bR.end());
        vec_a.emplace_back(cL); 

        ECPoint L = ECPointVector_Mul(vec_A, vec_a);  // Eq (23) 

        vec_A.clear(); vec_a.clear(); 

        vec_A.insert(vec_A.end(), vec_gL.begin(), vec_gL.end()); 
        vec_A.insert(vec_A.end(), vec_hR.begin(), vec_hR.end());
        vec_A.emplace_back(pp.u); 

        vec_a.insert(vec_a.end(), vec_aR.begin(), vec_aR.end()); 
        vec_a.insert(vec_a.end(), vec_bL.begin(), vec_bL.end());
        vec_a.emplace_back(cR); 

        ECPoint R = ECPointVector_Mul(vec_A, vec_a);  // Eq (24)

        proof.vec_L.push_back(L); 
        proof.vec_R.push_back(R);  // store the n-th round L and R values

        // compute the challenge
        transcript_str += ECPointToByteString(L) + ECPointToByteString(R); 
        BigInt x = HashToBigInt(transcript_str); // compute the n-th round challenge Eq (26,27)

        // x.Print(); 
        BigInt x_inverse = x.ModInverse(order);
        // generate new pp
        InnerProduct_PP pp_sub;
        // pp_sub.VECTOR_LEN = pp.VECTOR_LEN/2; 
        // pp_sub.LOG_VECTOR_LEN = pp.LOG_VECTOR_LEN - 1;  
        InnerProduct_Setup(pp_sub, pp.VECTOR_LEN/2, false);

        // compute vec_g
        ECPointVector_Scalar(vec_gL, vec_gL, x_inverse); 
        ECPointVector_Scalar(vec_gR, vec_gR, x); 
        ECPointVector_Add(pp_sub.vec_g, vec_gL, vec_gR); // Eq (29)

        // compute vec_h
        ECPointVector_Scalar(vec_hL, vec_hL, x); 
        ECPointVector_Scalar(vec_hR, vec_hR, x_inverse); 
        ECPointVector_Add(pp_sub.vec_h, vec_hL, vec_hR); // Eq (30)

        // generate new instance
        InnerProduct_Instance instance_sub; 
 
        pp_sub.u = pp.u; // pp_sub.u = pp.u 
 
        BigInt x_square = x.ModSquare(order); // vec_x[0] = x^2 mod q
        BigInt x_inverse_square = x_inverse.ModSquare(order); // vec_x[0] = x^2 mod q

        vec_A.clear(); 
        vec_a.clear();
        vec_A = {L, instance.P, R};  
        vec_a = {x_square, bn_1, x_inverse_square}; 

        //instance_sub.P = L * x_square + instance.P + R * x_inverse_square; 
        instance_sub.P = ECPointVector_Mul(vec_A, vec_a); // Eq (31) P' = L^{x^2} P R^{x^{-2}}

        // generate new witness
        InnerProduct_Witness witness_sub; 
        witness_sub.vec_a.resize(pp_sub.VECTOR_LEN); 
        witness_sub.vec_b.resize(pp_sub.VECTOR_LEN); 
    
        BigIntVector_ModScalar(vec_aL, vec_aL, x); 
        BigIntVector_ModScalar(vec_aR, vec_aR, x_inverse); 
        BigIntVector_ModAdd(witness_sub.vec_a, vec_aL, vec_aR); // Eq (33)

        BigIntVector_ModScalar(vec_bL, vec_bL, x_inverse); 
        BigIntVector_ModScalar(vec_bR, vec_bR, x); 
        BigIntVector_ModAdd(witness_sub.vec_b, vec_bL, vec_bR); // Eq (34)

        // recursively invoke the InnerProduct proof
        InnerProduct_Prove(pp_sub, instance_sub, witness_sub, transcript_str, proof); 
    }
}

/* Check if PI is a valid proof for inner product statement (G1^w = H1 and G2^w = H2) */
bool InnerProduct_Verify(InnerProduct_PP &pp, InnerProduct_Instance &instance, 
                         std::string &transcript_str, InnerProduct_Proof &proof)
{
    bool Validity;

    // recover the challenge
    std::vector<BigInt> vec_x(pp.LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    std::vector<BigInt> vec_x_square(pp.LOG_VECTOR_LEN); // the vector of challenge 
    std::vector<BigInt> vec_x_inverse_square(pp.LOG_VECTOR_LEN); // the vector of challenge inverse
    
    for (auto i = 0; i < pp.LOG_VECTOR_LEN; i++)
    {  
        transcript_str += ECPointToByteString(proof.vec_L[i]) + ECPointToByteString(proof.vec_R[i]); 
        vec_x[i] = HashToBigInt(transcript_str); // reconstruct the challenge

        vec_x_square[i] = vec_x[i].ModSquare(order); 
        vec_x_inverse[i] = vec_x[i].ModInverse(order);  
        vec_x_inverse_square[i] = vec_x_inverse[i].ModSquare(order); 
    }

    // define the left and right side of the equation on top of pp.17 (with slight modification)
    std::vector<ECPoint> vec_A; 
    std::vector<BigInt> vec_a; 

    // compute left
    std::vector<BigInt> vec_s(pp.VECTOR_LEN); 
    std::vector<BigInt> vec_s_inverse(pp.VECTOR_LEN); 


    ComputeVectorSS(vec_s, vec_x, vec_x_inverse); // page 15: the s vector
    BigIntVector_ModInverse(vec_s_inverse, vec_s);  // the s^{-1} vector
    BigIntVector_Scalar(vec_s, vec_s, proof.a); 
    BigIntVector_Scalar(vec_s_inverse, vec_s_inverse, proof.b); 

    vec_A.insert(vec_A.end(), pp.vec_g.begin(), pp.vec_g.end()); 
    vec_a.insert(vec_a.end(), vec_s.begin(), vec_s.end()); // pp.vec_g, vec_s

    vec_A.insert(vec_A.end(), pp.vec_h.begin(), pp.vec_h.end());
    vec_a.insert(vec_a.end(), vec_s_inverse.begin(), vec_s_inverse.end()); // pp.vec_h, vec_s_inverse

    vec_A.emplace_back(pp.u); 
    vec_a.emplace_back((proof.a * proof.b)); // LEFT = u^{ab}

    ECPoint LEFT = ECPointVector_Mul(vec_A, vec_a); 

    // compute right
    vec_A.clear(); vec_a.clear(); 
    vec_A.insert(vec_A.end(), proof.vec_L.begin(), proof.vec_L.end()); 
    vec_A.insert(vec_A.end(), proof.vec_R.begin(), proof.vec_R.end()); 

    vec_a.insert(vec_a.end(), vec_x_square.begin(), vec_x_square.end()); 
    vec_a.insert(vec_a.end(), vec_x_inverse_square.begin(), vec_x_inverse_square.end()); 

    vec_A.emplace_back(instance.P); 
    vec_a.emplace_back(bn_1); 

    ECPoint RIGHT = ECPointVector_Mul(vec_A, vec_a);  

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

#endif