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
#include "global.hpp"
#include "constants.h"
#include "openssl/evp.h"


//#define BasicHash(input, HASH_INPUT_LEN, output) SM3(input, HASH_INPUT_LEN, output)
#define BasicHash(input, HASH_INPUT_LEN, output) SHA256(input, HASH_INPUT_LEN, output)

namespace Hash{

// adaptor for SM3
void SM3(const unsigned char *input, size_t HASH_INPUT_LEN, unsigned char *output)
{
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
 
    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, input, HASH_INPUT_LEN);

    unsigned int md_len = HASH_OUTPUT_LEN; 
    EVP_DigestFinal_ex(md_ctx, output, &md_len);
    EVP_MD_CTX_free(md_ctx);
}


__attribute__((target("sse2")))
block StringToBlock(const std::string &str_input) 
{
    unsigned char output[HASH_OUTPUT_LEN];
    const unsigned char* input = reinterpret_cast<const unsigned char*>(str_input.c_str());
    size_t HASH_INPUT_LEN = str_input.length();
    BasicHash(input, HASH_INPUT_LEN, output); 
    //std::cout << "we are here" << std::endl;
    return _mm_load_si128((__m128i*)&output[0]);
}

BigInt StringToBigInt(const std::string& str_input){
    unsigned char output[HASH_OUTPUT_LEN]; 
    const unsigned char* input = reinterpret_cast<const unsigned char*>(str_input.c_str());
    size_t HASH_INPUT_LEN = str_input.length();
    BasicHash(input, HASH_INPUT_LEN, output); 

    BigInt result; 
    BN_bin2bn(output, HASH_OUTPUT_LEN, result.bn_ptr);
    return result; 
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

    return ecp_result;
}

block ECPointToBlock(const ECPoint &A) 
{
    std::string str_input = A.ToByteString();
    return StringToBlock(str_input);  
}

size_t AdHocECPointToIndex(const ECPoint &A)
{
    unsigned char buffer[POINT_BYTE_LEN];
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, nullptr);

    unsigned char input[BN_BYTE_LEN*2];
    memcpy(input, buffer+1, BN_BYTE_LEN*2); 

    // note that omp does not help to accelerate here
    block data[4]; 
    data[0] = _mm_load_si128((block *)(input+0 ));     
    data[1] = _mm_load_si128((block *)(input+16)); 
    data[2] = _mm_load_si128((block *)(input+32)); 
    data[3] = _mm_load_si128((block *)(input+48));

    AES::CBCEnc(fix_aes_enc_key, data, 4);  

    size_t index = _mm_cvtsi128_si64(data[3]);
    return index;
}

std::string ECPointToString(const ECPoint &A) 
{ 
    unsigned char input[POINT_COMPRESSED_BYTE_LEN];
    unsigned char output[HASH_OUTPUT_LEN]; 
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, input, POINT_COMPRESSED_BYTE_LEN, bn_ctx);
    
    size_t HASH_INPUT_LEN = POINT_COMPRESSED_BYTE_LEN;
    BasicHash(input, HASH_INPUT_LEN, output); 

    std::string str(reinterpret_cast<char *>(output), HASH_OUTPUT_LEN); 
    return str; 
}


block BlocksToBlock(const std::vector<block> &input_block)
{
    std::string str_input;
    for(auto i = 0; i < input_block.size(); i++){
        str_input += Block::ToString(input_block[i]);  
    }

    const unsigned char* input = reinterpret_cast<const unsigned char*>(str_input.c_str());
    size_t HASH_INPUT_LEN = str_input.length();
    unsigned char output[HASH_OUTPUT_LEN]; 
    BasicHash(input, HASH_INPUT_LEN, output); 

    return _mm_load_si128((__m128i*)&output[0]);
}

// fast block to ecpoint hash using low level openssl code
inline ECPoint BlockToECPoint(const block &var)
{
    //BN_CTX *temp_bn_ctx = BN_CTX_new(); 
    ECPoint ecp_result; 
 
    BIGNUM *x = BN_new();
    unsigned char buffer[32]; 
    memcpy(buffer, &var, 16); 
    BN_bin2bn(buffer, 16, x);
    
    BIGNUM *BN_3 = BN_new(); 
    BN_set_word(BN_3, 3); 

    BIGNUM *y_square = BN_new();
    BIGNUM *y = BN_new(); 
    BIGNUM *ax = BN_new(); 
    
    size_t LEN; 
    unsigned char hash_output[32]; 
    while (true) { 
        BN_exp(y_square, x, BN_3, bn_ctx); 
        BN_mul(ax, x, curve_params_a, bn_ctx);
        BN_add(y_square, y_square, ax); 
        BN_add(y_square, y_square, curve_params_b);   
        y = BN_mod_sqrt(y, y_square, curve_params_p, bn_ctx);
        // hash success
        if (y!= NULL){
            if(EC_POINT_set_affine_coordinates_GFp(group, ecp_result.point_ptr, x, y, bn_ctx)) break;
        }      
        LEN = BN_bn2bin(x, buffer); 
        BasicHash(buffer, LEN, hash_output);
        BN_bin2bn(hash_output, 32, x);
    }
    BN_free(BN_3); 
    BN_free(y); 
    BN_free(y_square); 
    BN_free(x); 
    BN_free(ax); 
    //BN_CTX_free(temp_bn_ctx); 
   
    return ecp_result;
}

// fast block to ecpoint hash using low level openssl code
inline ECPoint ThreadSafeBlockToECPoint(const block &var)
{
    BN_CTX *temp_bn_ctx = BN_CTX_new(); 
    ECPoint ecp_result; 
 
    BIGNUM *x = BN_new();
    unsigned char buffer[32]; 
    memcpy(buffer, &var, 16); 
    BN_bin2bn(buffer, 16, x);
    
    BIGNUM *BN_3 = BN_new(); 
    BN_set_word(BN_3, 3); 

    BIGNUM *y_square = BN_new();
    BIGNUM *y = BN_new(); 
    BIGNUM *ax = BN_new(); 
    
    size_t LEN; 
    unsigned char hash_output[32]; 
    while (true) { 
        BN_exp(y_square, x, BN_3, temp_bn_ctx); 
        BN_mul(ax, x, curve_params_a, temp_bn_ctx);
        BN_add(y_square, y_square, ax); 
        BN_add(y_square, y_square, curve_params_b);   
        y = BN_mod_sqrt(y, y_square, curve_params_p, temp_bn_ctx);
        // hash success
        if (y!= NULL){
            if(EC_POINT_set_affine_coordinates_GFp(group, ecp_result.point_ptr, x, y, temp_bn_ctx)) break;
        }      
        LEN = BN_bn2bin(x, buffer); 
        BasicHash(buffer, LEN, hash_output);
        BN_bin2bn(hash_output, 32, x);
    }
    BN_free(BN_3); 
    BN_free(y); 
    BN_free(y_square); 
    BN_free(x); 
    BN_free(ax); 
    BN_CTX_free(temp_bn_ctx); 
   
    return ecp_result;
}

/* map an EC point to another EC point, used in pp generation */
ECPoint ECPointToECPoint(ECPoint &g)
{
    ECPoint h; 
    unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
    unsigned char hash_output[HASH_OUTPUT_LEN]; 

    ECPoint ecp_trypoint = g;  

    /* continue the loop until find a point on curve */
    while(true){
        EC_POINT_point2oct(group, ecp_trypoint.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_COMPRESSED_BYTE_LEN, bn_ctx);
        BasicHash(buffer, POINT_BYTE_LEN, hash_output);
        // set h to be the first EC point sartisfying the following constraint
        if(EC_POINT_oct2point(group, h.point_ptr, hash_output, POINT_COMPRESSED_BYTE_LEN, bn_ctx) == 1 
           && EC_POINT_is_on_curve(group, h.point_ptr, bn_ctx) == 1
           && EC_POINT_is_at_infinity(group, h.point_ptr) == 0) break;
        else ecp_trypoint = ecp_trypoint + g; 
    } 
    return h; 
}

}

#endif //_HASH_HPP_

