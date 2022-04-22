/*
** Modified from the following project
** 1. https://github.com/emp-toolkit/
*/

#ifndef KUNLUN_AES_HPP_
#define KUNLUN_AES_HPP_

#include "block.hpp"

namespace AES{

static const block IV = Block::zero_block; 

struct Key{ 
    block roundkey[11]; 
    size_t ROUND_NUM; 
};

#define EXPAND_ASSIST(v1, v2, v3, v4, SHUFFLE_CONST, AES_CONST)                               \
    v2 = _mm_aeskeygenassist_si128(v4, AES_CONST);                                          \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3), _mm_castsi128_ps(v1), 16));  \
    v1 = _mm_xor_si128(v1,v3);                                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3), _mm_castsi128_ps(v1), 140)); \
    v1 = _mm_xor_si128(v1,v3);                                                              \
    v2 = _mm_shuffle_epi32(v2, SHUFFLE_CONST);                                                \
    v1 = _mm_xor_si128(v1,v2)


__attribute__((target("aes,sse2")))
inline Key GenEncKey(const block &salt) {
    Key enc_key; 
    block x0, x1, x2;
    enc_key.roundkey[0] = x0 = salt;
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);
    enc_key.roundkey[1] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);
    enc_key.roundkey[2] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);
    enc_key.roundkey[3] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);
    enc_key.roundkey[4] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);
    enc_key.roundkey[5] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);
    enc_key.roundkey[6] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);
    enc_key.roundkey[7] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 128);
    enc_key.roundkey[8] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);
    enc_key.roundkey[9] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);
    enc_key.roundkey[10] = x0;
    enc_key.ROUND_NUM = 10;

    return enc_key; 
}

__attribute__((target("aes,sse2")))
inline Key DeriveDecKeyFromEncKey(const Key &enc_key) {
    Key dec_key; 
    dec_key.ROUND_NUM = enc_key.ROUND_NUM;
    int j = 0;
    int i = dec_key.ROUND_NUM; 

    dec_key.roundkey[i--] = enc_key.roundkey[j++];
    while (i >= 1)
        dec_key.roundkey[i--] = _mm_aesimc_si128(enc_key.roundkey[j++]);
    dec_key.roundkey[i] = enc_key.roundkey[j];
    return dec_key; 
}

// to ensure correct decryption, the salt should be same
__attribute__((target("aes,sse2")))
inline Key GenDecKey(const block &salt) {
    Key enc_key = GenEncKey(salt);
    return DeriveDecKeyFromEncKey(enc_key);
}

__attribute__((target("aes,sse2")))
inline void Enc(const Key &key, block &data) 
{
    data = _mm_xor_si128(data, key.roundkey[0]);
    for (auto j = 1; j < key.ROUND_NUM; j++)
        data = _mm_aesenc_si128(data, key.roundkey[j]);
    data = _mm_aesenclast_si128(data, key.roundkey[key.ROUND_NUM]);
}

__attribute__((target("aes,sse2")))
inline void Dec(const Key &key, block &data) 
{
    data = _mm_xor_si128(data, key.roundkey[0]);
    for (auto j = 1; j < key.ROUND_NUM; j++)
        data = _mm_aesdec_si128(data, key.roundkey[j]);
    data = _mm_aesdeclast_si128(data, key.roundkey[key.ROUND_NUM]);
}

__attribute__((target("aes,sse2")))
inline void ECBEnc(const Key &key, block* data, size_t BLOCK_LEN) 
{
    #pragma omp parallel for
    for (auto i = 0; i < BLOCK_LEN; i++)
        Enc(key, data[i]);
}

/*
** this implementation is less modular and cumbersome 
** but more efficient since it unroll the loop
*/
__attribute__((target("aes,sse2")))
inline void FastECBEnc(const Key &key, block *data, size_t BLOCK_LEN) 
{
    const size_t BATCH_SIZE = 8;
    size_t LEN = BLOCK_LEN - BLOCK_LEN % BATCH_SIZE; // ensure LEN = 8*n

	block temp[BATCH_SIZE];

    for (auto i = 0; i < LEN; i += BATCH_SIZE)
    {
        for (auto j = 0; j < BATCH_SIZE; j++)
            temp[j] = _mm_xor_si128(data[i + j], key.roundkey[0]);

        for (auto k = 1; k < key.ROUND_NUM; k++)
            for (auto j = 0; j < BATCH_SIZE; j++)
                temp[j] = _mm_aesenc_si128(temp[j], key.roundkey[k]);
        
        for (auto j = 0; j < BATCH_SIZE; j++)
            data[i + j] = _mm_aesenclast_si128(temp[j], key.roundkey[key.ROUND_NUM]);
    }

    for (auto i = LEN; i < BLOCK_LEN; i++)
    {
        data[i] = _mm_xor_si128(data[i], key.roundkey[0]);
        for (auto k = 1; k < key.ROUND_NUM; k++)
            data[i] = _mm_aesenc_si128(data[i], key.roundkey[k]);
        data[i] = _mm_aesenclast_si128(data[i], key.roundkey[key.ROUND_NUM]);
    }
}

__attribute__((target("aes,sse2")))
inline void ECBDec(const Key &key, block* data, size_t BLOCK_LEN) 
{
    #pragma omp parallel for
    for (auto i = 0; i < BLOCK_LEN; i++)
        Dec(key, data[i]);
}

__attribute__((target("aes,sse2")))
inline void CBCEnc(const Key &key, block* data, size_t BLOCK_LEN) 
{
    data[0] = _mm_xor_si128(data[0], IV);
    Enc(key, data[0]);    
    for (auto i = 1; i < BLOCK_LEN; i++)
    {
        data[i] = _mm_xor_si128(data[i], data[i-1]);
        Enc(key, data[i]);
    }
}


__attribute__((target("aes,sse2")))
inline void CBCDec(const Key &key, block* data, size_t BLOCK_LEN) 
{
    for (auto i = BLOCK_LEN-1; i > 0; i--)
    {
        Dec(key, data[i]);
        data[i] = _mm_xor_si128(data[i], data[i-1]);
    } 
    Dec(key, data[0]);    
    data[0] = _mm_xor_si128(data[0], IV);
}

}
#endif


