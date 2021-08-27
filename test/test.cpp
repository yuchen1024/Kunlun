//#define DEBUG
#include "../source/bigint.hpp"
#include "../source/ec_point.hpp"
#include <iostream>

int main()
{
    ContextInitialize(); 
    ECGroupInitialize(NID_X9_62_prime256v1); 
    BigInt a(1); 
    BigInt b(2);
    BigInt c;
    c = bn_2 + bn_2;
    std::cout << c.ToDecimalString() << std::endl;
    ECPoint A;
    ECPoint B; 
    B = A.Mul(c);
    ECGroupFinalize(); 
    ContextFinalize(); 
    return 0;   
}

