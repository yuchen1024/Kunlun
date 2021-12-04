#ifndef POLY_MUL_HPP_
#define POLY_MUL_HPP_
 
// A[] represents coefficients of first polynomial
// B[] represents coefficients of second polynomial
std::vector<BigInt> PolyMul(std::vector<BigInt> A, std::vector<BigInt> B)
{
    // Initialize the product polynomial
    std::vector<BigInt> C(A.size() + B.size()-1, bn_0);  
   
    // Multiply two polynomials term by term
    // Take ever term of first polynomial
    for (auto i = 0; i < A.size(); i++){
        // Multiply the current term of first polynomial with every term of second polynomial.
        for (auto j = 0; j < B.size(); j++)
            C[i+j] = (C[i+j] + A[i] * B[j]) % order;
    }
 
    return C;
}

// result = P[0]*...P[n-1]
std::vector<BigInt> PolyMul(std::vector<std::vector<BigInt>> P)
{
    std::vector<BigInt> result(1, bn_1); 
    for(auto i = 0; i < P.size(); i++){
        result = PolyMul(result, P[i]); 
    }
    return result; 
}

// A utility function to print a polynomial
void PrintPoly(std::vector<BigInt> P)
{
    for (auto i = 0; i < P.size(); i++){
       P[i].PrintInDec();
       if (i != 0) std::cout << "*x^" << i;
       if (i != P.size()-1) std::cout << " + ";
    }
    std::cout << std::endl;
}

// A utility function to print a polynomial
BigInt EvalPoly(std::vector<BigInt> P, BigInt x)
{
    BigInt result = bn_0;
    BigInt carry = bn_1;  
    for (auto i = 0; i < P.size(); i++){
       result += (P[i] * carry) % order; 
       carry *= x; 
    }
    return result % order; 
}

#endif