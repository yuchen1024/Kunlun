/****************************************************************************
this hpp file define and initialize misc global variables 
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_GLOBAL_HPP_
#define KUNLUN_GLOBAL_HPP_

#include "../include/std.inc"
//#include "constants.h"
#include "aes.hpp"

const static size_t AES_BATCH_SIZE = 8;
const static size_t HASH_BUFFER_SIZE = 1024*8;
const static size_t NETWORK_BUFFER_SIZE = 1024*1024;
const static size_t FILE_BUFFER_SIZE = 1024*16;
const static size_t CHECK_BUFFER_SIZE = 1024*8;

const static size_t HASH_OUTPUT_LEN = 32;  // hash output = 256-bit string

const char fix_key[] = "\x61\x7e\x8d\xa2\xa0\x51\x1e\x96\x5e\x41\xc2\x9b\x15\x3f\xc7\x7a";

const static uint64_t fixed_salt = 0xAAAAAAAA; // used for murmurhash

const static size_t thread_count = 8; // maximum thread count 

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
