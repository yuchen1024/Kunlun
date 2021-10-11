#ifndef KUNLUN_PRP_HPP_
#define KUNLUN_PRP_HPP_
#include "emp-tool/utils/block.h"
#include "emp-tool/utils/constants.h"
#include "emp-tool/utils/aes.h"

/*
 * When the key is public, we usually need to model AES with this public key as a random permutation.
 * [REF] "Efficient Garbling from a Fixed-Key Blockcipher" https://eprint.iacr.org/2013/426.pdf
*/

namespace PRP{

struct PRP_Key{
    AES_KEY key;
}; 

void PRP_Set_Key(PRP_Key &key, const block* v)
{
    if(userkey == nullptr) AES_Set_Encrypt_Key(zero_block, key);
    else AES_Set_Encrypt_Key(v, key);
}

void PRP_Permutation(PRP_Key &key, block *data, size_t BLOCK_NUM) {
    for(auto i = 0; i < BLOCK_NUM/AES_BATCH_SIZE; i++) 
    {
        AES_ECB_Encrypt(data + i*AES_BATCH_SIZE, AES_BATCH_SIZE, key);
    }
    size_t REMAIN_NUM = BLOCK_NUM % AES_BATCH_SIZE;
    AES_ECB_Encrypt(key, data + BLOCK_NUM - REMAIN_NUM, REMAIN_NUM);
    
}

}
#endif