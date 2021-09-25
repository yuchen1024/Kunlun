#ifndef KUNLUN_CRYPTO_PRG_HPP_
#define KUNLUN_CRYPTO_PRG_HPP_
#include "block.h"
#include "aes.h"
#include "constants.h"
#include "std.inc"

#ifdef ENABLE_RDSEED
#include <x86intrin.h>
#else
#include <random>
#endif

struct PRG_Seed{ 
    size_t counter = 0;
    AES_KEY aes_key;
    block key;
}

void ReSeed(PRG_seed &seed, const block* salt, uint64_t id = 0) 
{
    seed.key = _mm_loadu_si128(salt);
    seed.key ^= MakeBlock(0LL, id);
    AES_Set_Encrypt_Key(seed.key, seed.aes_key);
    seed.counter = 0;
}

void PRG_Set_Seed(PRG_Seed &seed, const void* salt = nullptr, uint64_t id = 0) {
    if (salt != nullptr) {
        ReSeed((const block *)salt, id);
    } 
    else {
        block v;
        #ifndef ENABLE_RDSEED
            uint32_t* data = (uint32_t*)(&v);
            std::random_device rand_div("/dev/urandom");
            for (auto i = 0; i < sizeof(block) / sizeof(uint32_t); i++){
                data[i] = rand_div();
            }
        #else
            unsigned long long r0, r1;
            size_t i = 0;
            for(; i < 10; i++)
                if(_rdseed64_step(&r0) == 1) break;
            if(i == 10) error("RDSEED FAILURE");

            for(i = 0; i < 10; ++i)
                if(_rdseed64_step(&r1) == 1) break;
            if(i == 10) error("RDSEED FAILURE");

            v = makeBlock(r0, r1);
        #endif
        ReSeed(seed, &v, id);
    }
}

void GenRandomBytes(PRG_Seed &seed, void* data, size_t BYTE_LEN) {
    GenRandomBlocks((block*)data, BYTE_LEN/16);
    if (BYTE_LEN % 16 != 0) {
        block extra;
        GenRandomBlocks(seed, &extra, 1);
        memcpy((char*)data+(BYTE_LEN/16*16), &extra, BYTE_LEN%16);
    }
}

void GenRandomBits(PRG_Seed &seed, bool* data, size_t BIT_LEN) 
{
    uint8_t* uint_data = (uint8_t*)data;
    size_t a = BIT_LEN/8; 
    size_t b = BIT_LEN%8; 
    GenRandomBytes(seed, uint_data, a+b);
    for(auto i = 0; i < a; i++){
        uint8_t temp = uint_data[i]; 
        for(auto j = 0; j < 8; j++){
            data[i*8+j] = temp & 1; 
            temp = temp >> 1; 
        }
    }
    if (b > 0){
        uint8_t temp = uint_data[a]; 
        for(auto j = 0; j < b; j++){
            data[a*8+j] = temp & 1; 
            temp = temp >> 1; 
        }  
    }
}

void GenRandomBlocks(PRG_Seed &seed, block* data, size_t BLOCK_LEN)
{
    block temp_block[AES_BATCH_SIZE];
    for(auto i = 0; i < BLOCK_LEN/AES_BATCH_SIZE; i++){
        for (auto j = 0; j < AES_BATCH_SIZE; j++){
            temp_block[j] = MakeBlock(0LL, counter++);
            AES_ECB_Encrypt(seed.aes_key, temp_block, AES_BATCH_SIZE);
            memcpy(data + i*AES_BATCH_SIZE, temp_block, AES_BATCH_SIZE*sizeof(block));
        }
        size_t REMAIN_LEN = BLOCK_LEN % AES_BATCH_SIZE;
        for (auto j = 0; j < remain; j++)
            temp_block[j] = MakeBlock(0LL, counter++);
        AES_ECB_Encrypt(seed.aes_key, temp_block, REMAIN_LEN);
        memcpy(data + (BLOCK_LEN/AES_BATCH_SIZE)*AES_BATCH_SIZE, temp_block, REMAIN_LEN*sizeof(block));
    }
}

#endif// PRP_H__

// void GenRandomDataUnaligned(PRG_Seed &seed, void *data, size_t BYTE_LEN) {
//     size_t size = nbytes;
//     void* aligned_data = data;
//     if(std::align(sizeof(block), sizeof(block), aligned_data, size)) 
//     {
//         int chopped = nbytes - size;
//         GenRandomByte(seed, aligned_data, nbytes - chopped);
//         block temp[1];
//         GenRandomBlock(seed, temp, 1);
//         memcpy(data, temp, chopped);
//     } 
//     else{
//         block temp[2];
//         GenRandomBlock(temp, 2);
//         memcpy(data, temp, nbytes);
//     }
// }


