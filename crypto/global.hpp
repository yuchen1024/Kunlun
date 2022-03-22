/****************************************************************************
this hpp file define and initialize misc global variables 
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_GLOBAL_HPP_
#define KUNLUN_GLOBAL_HPP_

#include "../include/std.inc"
#include "constants.h"
#include "aes.hpp"
#include "block.hpp"

static AES::Key fix_aes_enc_key; // global aes enc key
static AES::Key fix_aes_dec_key; // global aes dec key

void Global_Setup()
{
    //uint64_t aes_salt[2] = {0LL, 0xAAAAAAAA};
    //block salt = _mm_loadu_si128((const block*) aes_salt); 
    block salt = Block::zero_block;
  
    fix_aes_enc_key = AES::GenEncKey(salt); 
    fix_aes_dec_key = AES::DeriveDecKeyFromEncKey(fix_aes_enc_key); 
}


#endif
