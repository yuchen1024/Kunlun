/****************************************************************************
this hpp implements hash functions 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_CRYPTO_HASH_HPP_
#define KUNLUN_CRYPTO_HASH_HPP_

#include "../include/global.hpp"
#include "bigint.hpp"
#include "ec_point.hpp"

inline const size_t HASH_BUFFER_SIZE = 1024*8;
inline const size_t HASH_OUTPUT_LEN = 32;  // hash output = 256-bit string

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
    AES::CBCEnc(AES::fixed_enc_key, data, BLOCK_NUM);  

    _mm_storeu_si128((block*)output, data[BLOCK_NUM-1]);
}

// dedicated CBCAES that hash 32 bytes input to 32 bytes output
void Dedicated_CBCAES(const uint8_t* input, uint8_t* output) 
{
    block data[2];
    data[0] = _mm_load_si128((block *)(input));
    data[1] = _mm_load_si128((block *)(input + 16));

    // use CBC-AES hash: digest lies in the last block
    AES::CBCEnc(AES::fixed_enc_key, data, 2);  

    _mm_storeu_si128((block*)output, data[0]);
    _mm_storeu_si128((block*)(output+16), data[1]);
}

__attribute__((target("sse2")))
block StringToBlock(const std::string &str_input) 
{
    unsigned char output[HASH_OUTPUT_LEN];
    BasicHash(reinterpret_cast<const unsigned char*>(str_input.c_str()), str_input.length(), output); 
    return _mm_load_si128((block*)&output[0]);
}

__attribute__((target("sse2")))
block BytesToBlock(const std::vector<uint8_t> &vec_A) 
{
    unsigned char output[HASH_OUTPUT_LEN];
    BasicHash(vec_A.data(), vec_A.size(), output); 
    return _mm_load_si128((block*)&output[0]);
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

std::string ECPointToString(const ECPoint &A) 
{ 
    int thread_num = omp_get_thread_num();
    unsigned char input[POINT_COMPRESSED_BYTE_LEN];
    unsigned char output[HASH_OUTPUT_LEN]; 
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, input, POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
    
    size_t HASH_INPUT_LEN = POINT_COMPRESSED_BYTE_LEN;
    BasicHash(input, HASH_INPUT_LEN, output); 

    std::string str(reinterpret_cast<char *>(output), HASH_OUTPUT_LEN); 
    return str; 
}

std::vector<uint8_t> ECPointToBytes(const ECPoint &A) 
{ 
    int thread_num = omp_get_thread_num();
    unsigned char input[POINT_COMPRESSED_BYTE_LEN];
    unsigned char output[HASH_OUTPUT_LEN]; 
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, input, POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
    
    size_t HASH_INPUT_LEN = POINT_COMPRESSED_BYTE_LEN;
    BasicHash(input, HASH_INPUT_LEN, output);

    std::vector<uint8_t> result(HASH_OUTPUT_LEN); 
    memcpy(result.data(), output, HASH_OUTPUT_LEN);

    return result; 
}

// Hash-based blocks to block hash
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

// AES-based blocks to block hash, which is faster than hash-based counterpart
block FastBlocksToBlock(const std::vector<block> input_block)
{
    std::vector<block> vec_B = input_block;
    // use CBC-AES hash: digest lies in the last block
    size_t BLOCK_NUM = vec_B.size();
    AES::CBCEnc(AES::fixed_enc_key, vec_B.data(), BLOCK_NUM);  
    return vec_B[BLOCK_NUM-1];
}


// /* 
// ** AES-based block to block hash
// ** though this function can be performed by the above one
// ** it is worthwhile to give a dedicated on for efficiency
// */
// block FastBlockToBlock(const std::vector<block> input_block)
// {
//     block output_block = input_block;
//     AES::Enc(AES::fixed_enc_key, output_block);  
//     return output_block;
// }


/* 
* hash a block to uint8_t[32]
* must guranttee output[] has at least LEN bytes space 
*/
int BlockToBytes(const block &var, uint8_t* output, size_t LEN)
{
    if(HASH_OUTPUT_LEN < LEN){
        std::cerr << "digest is too short for desired length" << std::endl;
        return 0;     
    }

    memset(output, 0, 32);
    memcpy(output, &var, 16); // set the block as input of hash
    Dedicated_CBCAES(output, output); 
    //BasicHash(output, 16, output); // compute the hash value

    return 1; 
}

// fast and threadsafe block to ecpoint hash using low level openssl code
inline ECPoint BlockToECPoint(const block &var)
{
    int thread_num = omp_get_thread_num();
    ECPoint ecp_result; 
    BIGNUM *x = BN_new();
    uint8_t buffer[32]; 
    memset(buffer, 0, 32); 
    memcpy(buffer, &var, 16); // set the block as input of hash
    Dedicated_CBCAES(buffer, buffer); // initial hash to get the indication bit of y coordinate
    // BasicHash(buffer, 32, buffer); 
    int y_bit = 0x01 & buffer[0]; // this is an ad-hoc method: set y_bit as one bit of buffer[0]
    while (true) { 
        Dedicated_CBCAES(buffer, buffer); // iterated hash, modeled as random oracle
        // BasicHash(buffer, 32, buffer); 
        BN_bin2bn(buffer, 32, x);
        if(EC_POINT_set_compressed_coordinates(group, ecp_result.point_ptr, x, y_bit, bn_ctx[thread_num])==1) break;              
    }
    BN_free(x);    
    return ecp_result;
}


}

#endif //_HASH_HPP_

