/*
** Modified from the following project
** 1. https://github.com/emp-toolkit/
*/

#ifndef KUNLUN_CRYPTO_PRG_HPP_
#define KUNLUN_CRYPTO_PRG_HPP_


#include "aes.hpp"
#include "global.hpp"

#ifdef ENABLE_RDSEED
#include <x86intrin.h>
#else
#include <random>
#endif

namespace PRG{

struct Seed{ 
    size_t counter = 0; 
    AES::Key aes_key;
};

void ReSeed(Seed &seed, const block* salt, uint64_t id = 0) 
{
    block key = _mm_loadu_si128(salt);
    key ^= Block::MakeBlock(0LL, id);
    seed.aes_key = AES::GenEncKey(key);
    seed.counter = 0;
}
// id is the identidier of PRG in use
Seed SetSeed(const void* salt = nullptr, uint64_t id = 0) {
    Seed seed; 
    // if there is a given salt
    if (salt != nullptr) {
        ReSeed(seed, (const block *)salt, id);
    } 
    // if there is no given salt
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

            v = Block::MakeBlock(r0, r1);
        #endif
        ReSeed(seed, &v, id);
    }
    seed.counter = 0; 
    return seed; 
}

std::vector<block> GenRandomBlocks(Seed &seed, size_t LEN)
{
    std::vector<block> vec_b(LEN); 
    block temp_block[AES_BATCH_SIZE];
    for(auto i = 0; i < LEN/AES_BATCH_SIZE; i++){
        for (auto j = 0; j < AES_BATCH_SIZE; j++)
            temp_block[j] = Block::MakeBlock(0LL, seed.counter++);
        AES::FastECBEnc(seed.aes_key, temp_block, AES_BATCH_SIZE);
        memcpy(vec_b.data() + i*AES_BATCH_SIZE, temp_block, AES_BATCH_SIZE*sizeof(block));
    }
    size_t REMAIN_LEN = LEN % AES_BATCH_SIZE;
    for (auto j = 0; j < REMAIN_LEN; j++)
        temp_block[j] = Block::MakeBlock(0LL, seed.counter++);
    AES::FastECBEnc(seed.aes_key, temp_block, REMAIN_LEN);
    memcpy(vec_b.data()+(LEN/AES_BATCH_SIZE)*AES_BATCH_SIZE, temp_block, REMAIN_LEN*sizeof(block));

    return vec_b; 
}


// generate a random byte vector
std::vector<uint8_t> GenRandomBytes(Seed &seed, size_t LEN){
    std::vector<uint8_t> vec_b(LEN);
    size_t BLOCK_LEN = size_t(ceil(double(LEN)/16)); 
    std::vector<block> vec_a(BLOCK_LEN); 
    vec_a = GenRandomBlocks(seed, BLOCK_LEN);

    memcpy(vec_b.data(), vec_a.data(), LEN); 

    return vec_b; 
}

// generate a random bool vector: each byte represent a bit in a sparse way
std::vector<uint8_t> GenRandomBits(Seed &seed, size_t LEN) 
{
    std::vector<uint8_t> vec_b; // interpret each byte as a bit
    vec_b = GenRandomBytes(seed, LEN);
    for(auto i = 0; i < LEN; i++){
        vec_b[i] = vec_b[i] & 1;
    }
    return vec_b; 
}

// generate a random bit matrix (store in column vector order) in byte form
// std::vector<uint8_t> GenRandomBitMatrix(Seed &seed, size_t ROW_NUM, size_t COLUMN_NUM)
// {
//     assert(ROW_NUM % 8 == 0 && COLUMN_NUM % 8 == 0);
//     // pack 8-bits into 1-byte
//     std::vector<uint8_t> T(ROW_NUM/8 * COLUMN_NUM); 

//     std::vector<uint8_t> random_column(ROW_NUM/8); 
    
//     // generate the i-th row
//     for(auto i = 0; i < COLUMN_NUM; i++){
//         random_column = GenRandomBytes(seed, ROW_NUM/8);
//         memcpy(T.data()+i*ROW_NUM/8, random_column.data(), ROW_NUM/8);  
//     }
//     return T;
// }

// generate a random bit matrix (store in column vector order) in block form
std::vector<block> GenRandomBitMatrix(Seed &seed, size_t ROW_NUM, size_t COLUMN_NUM)
{
    assert(ROW_NUM % 128 == 0 && COLUMN_NUM % 8 == 0);
    std::vector<block> T = GenRandomBlocks(seed, ROW_NUM/128 * COLUMN_NUM);
    return T;
} 


}

bool CompareBits(std::vector<uint8_t>& vec_A,  std::vector<uint8_t>& vec_B)
{
    bool flag = true; 
    if(vec_A.size()!=vec_B.size()){
        std::cerr << "sizes of bits vector do not match" << std::endl;
        return false; 
    }
    for(auto i = 0; i < vec_A.size(); i++){
        if(vec_A[i] != vec_B[i]){
            std::cerr << i << "th position does not match" << std::endl;
            std::cout << static_cast<int>(vec_A[i]) << std::endl; 
            std::cout << static_cast<int>(vec_B[i]) << std::endl; 

            flag = false;
        }
    }
    return flag; 
}



#endif// PRP_H__




