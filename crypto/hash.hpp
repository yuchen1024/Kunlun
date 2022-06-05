/****************************************************************************
this hpp implements hash functions 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_CRYPTO_HASH_HPP_
#define KUNLUN_CRYPTO_HASH_HPP_

#include "global.hpp"
// #include "constants.h"
#include "block.hpp"
#include "bigint.hpp"
#include "ec_point.hpp"


//#define BasicHash(input, HASH_INPUT_LEN, output) SM3(input, HASH_INPUT_LEN, output)
#define BasicHash(input, HASH_INPUT_LEN, output) SHA256(input, HASH_INPUT_LEN, output)

namespace Hash{

// adaptor for SM3: default output length is 256 bit
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

// adaptor for CBC-AES hash: default output length is 128 bit
void CBCAES(const unsigned char *input, size_t HASH_INPUT_LEN, unsigned char *output) 
{
    // pad input to 16*n bytes: 16*(INPUT_LEN % 16 + 1)
    size_t PADDED_LEN = ((HASH_INPUT_LEN + 0x0F) >> 4) << 4; // ((LEN+15)/16)*16

    // padding method to be refined
    size_t BLOCK_NUM = (PADDED_LEN >> 4); // 16 bytes = 1 block
    unsigned char buffer[PADDED_LEN]; 
    memset(buffer, 0, PADDED_LEN); 
    memcpy(buffer, input, HASH_INPUT_LEN); 

    block data[BLOCK_NUM];
    for(auto i = 0; i < BLOCK_NUM; i++){
        data[i] = _mm_load_si128((block *)(input + i*16));
    } 

    // use CBC-AES hash: digest lies in the last block
    AES::CBCEnc(fix_aes_enc_key, data, BLOCK_NUM);  

    _mm_storeu_si128((block *)output, data[BLOCK_NUM-1]);
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

// block ThreadSafeECPointToBlock(const ECPoint &A) 
// {
//     std::string str_input = A.ThreadSafeToByteString();
//     return StringToBlock(str_input);  
// }


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

block FastBlocksToBlock(const std::vector<block> input_block)
{
    std::vector<block> vec_B = input_block;
    // use CBC-AES hash: digest lies in the last block
    size_t BLOCK_NUM = vec_B.size();
    AES::CBCEnc(fix_aes_enc_key, vec_B.data(), BLOCK_NUM);  
    return vec_B[BLOCK_NUM-1];
}


// fast and threadsafe block to ecpoint hash using low level openssl code
inline ECPoint BlockToECPoint(const block &var)
{
    ECPoint ecp_result; 
 
    BIGNUM *x = BN_new();
    unsigned char buffer[32];
    memset(buffer, 0, 32);
    memcpy(buffer, &var, 16);    
    while (true) { 
        BN_bin2bn(buffer, 32, x);
        if(EC_POINT_set_compressed_coordinates(group, ecp_result.point_ptr, x, 0, ec_ctx)==1) break;      
        BasicHash(buffer, 32, buffer);
    }
    BN_free(x);    
    return ecp_result;
}

// // fast block to ecpoint hash using low level openssl code
// inline ECPoint ThreadSafeBlockToECPoint(const block &var)
// {
//     BN_CTX *temp_bn_ctx = BN_CTX_new(); 
//     ECPoint ecp_result; 
 
//     BIGNUM *x = BN_new();
//     // unsigned char buffer[32];
//     // memset(buffer, 0, 32);
//     // memcpy(buffer, &var, 16);    
//     block buffer[2];
//     buffer[0] = Block::zero_block;
//     buffer[1] = var; 
//     AES::CBCEnc(fix_aes_enc_key, buffer, 2); 
//     while (true) { 
//         BN_bin2bn((unsigned char*)buffer, 32, x);
//         if(EC_POINT_set_compressed_coordinates(group, ecp_result.point_ptr, x, 0, temp_bn_ctx) ==1) break;      
//         //BasicHash(buffer, 32, buffer);
//         AES::CBCEnc(fix_aes_enc_key, buffer, 2); 
//     }
//     BN_free(x);    
//     BN_CTX_free(temp_bn_ctx); 
   
//     return ecp_result;
// }

}

#endif //_HASH_HPP_

