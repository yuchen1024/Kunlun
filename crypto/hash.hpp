/****************************************************************************
this hpp implements hash functions 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_CRYPTO_HASH_HPP_
#define KUNLUN_CRYPTO_HASH_HPP_

#include "block.hpp"
#include "bigint.hpp"
#include "ec_point.hpp"
#include "constants.h"

namespace Hash{

void StringToCharArray(const std::string &input, unsigned char* digest)
{
    SHA256_CTX sha256; 
    SHA256_Init(&sha256); 
    SHA256_Update(&sha256, input.c_str(), input.length()); 
    SHA256_Final(digest, &sha256); 
}

__attribute__((target("sse2")))
block StringToBlock(const std::string &input) 
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    StringToCharArray(input, digest); 
    //std::cout << "we are here" << std::endl;
    return _mm_load_si128((__m128i*)&digest[0]);
}

BigInt StringToBigInt(const std::string& input){
    unsigned char digest[SHA256_DIGEST_LENGTH]; 
    StringToCharArray(input, digest); 

    BigInt result; 
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, result.bn_ptr);
    return std::move(result); 
}

ECPoint StringToECPoint(const std::string& input) 
{
    ECPoint ecp_result; 

    BigInt p = BigInt(curve_params_p); 
    BigInt x = StringToBigInt(input);
    BigInt y_square, y; 

    x = x.Mod(p);    
    while (true) {
        // Try Hash BigInt x To ECPoint 
        y_square = (x.Exp(bn_3) + BigInt(curve_params_a) * x + BigInt(curve_params_b)).Mod(BigInt(curve_params_p));
        // hash success
        if (IsSquare(y_square)){
            y = y_square.ModSquareRoot(curve_params_p);
            if (y.IsBitSet(0)){
                ecp_result = CreateECPoint(x, y.ModNegate(curve_params_p));
            }
            ecp_result = CreateECPoint(x, y);
            break;
        }
        // hash fails: continue try with a new value
        x = StringToBigInt(x.ToByteString()); 
    }

    return std::move(ecp_result);
}


block ECPointToBlock(const ECPoint &A) 
{
    std::string str_input = A.ToByteString();
    return StringToBlock(str_input);  
}


block BlocksToBlock(const std::vector<block> &input)
{

    SHA256_CTX sha256; 
    SHA256_Init(&sha256); 
    std::string str_input;
    for(auto i = 0; i < input.size(); i++){
        str_input = Block::ToString(input[i]); 
        SHA256_Update(&sha256, str_input.c_str(), str_input.length()); 
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &sha256); 
    return _mm_load_si128((__m128i*)&digest[0]);
}

/* map an EC point to another EC point, used in pp generation */
ECPoint ECPointToECPoint(ECPoint &g)
{
    ECPoint h; 
    unsigned char buffer[POINT_BYTE_LEN];
    unsigned char hash_output[HASH_OUTPUT_LEN]; 

    ECPoint ecp_trypoint = g;  

    /* continue the loop until find a point on curve */
    while(true){
        EC_POINT_point2oct(group, ecp_trypoint.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, bn_ctx);
        SHA256(buffer, POINT_BYTE_LEN, hash_output);
        // set h to be the first EC point sartisfying the following constraint
        if(EC_POINT_oct2point(group, h.point_ptr, hash_output, POINT_BYTE_LEN, bn_ctx) == 1 
           && EC_POINT_is_on_curve(group, h.point_ptr, bn_ctx) == 1
           && EC_POINT_is_at_infinity(group, h.point_ptr) == 0) break;
        else ecp_trypoint = ecp_trypoint + g; 
    } 
    return std::move(h); 
}

}

#endif //_HASH_HPP_

