/****************************************************************************
this hpp file define and initialize misc global variables 
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_GLOBAL_HPP_
#define KUNLUN_GLOBAL_HPP_

#include "../include/std.inc"
#include "../include/openssl.inc"
#include "aes.hpp"

static size_t BN_BYTE_LEN;  // the byte length of bigint
//static size_t FIELD_BYTE_LEN;  // each scalar field element is 256 bit 
static size_t INT_BYTE_LEN;   // the byte length of built-in size_t

static BN_CTX *bn_ctx; 
static BN_CTX *ec_ctx; // define ctx for ecc operations

#define PARALLEL
const static size_t thread_count = 8; // maximum thread count 

const static size_t AES_BATCH_SIZE = 8;
const static size_t HASH_BUFFER_SIZE = 1024*8;
const static size_t NETWORK_BUFFER_SIZE = 1024*1024;
const static size_t FILE_BUFFER_SIZE = 1024*16;
const static size_t CHECK_BUFFER_SIZE = 1024*8;
const static size_t HASH_OUTPUT_LEN = 32;  // hash output = 256-bit string

const char fix_key[] = "\x61\x7e\x8d\xa2\xa0\x51\x1e\x96\x5e\x41\xc2\x9b\x15\x3f\xc7\x7a";

const static uint64_t fixed_salt = 0xAAAAAAAA; // used for murmurhash

static AES::Key fix_aes_enc_key; // global aes enc key
static AES::Key fix_aes_dec_key; // global aes dec key

// return the error message reported by OpenSSL
void CRYPTO_CHECK(bool condition){
    if (condition == false){
        char buffer[256];
        ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
        std::cerr << std::string(buffer);
    }
} 

void LoadErrorStrings(){
    ERR_load_BN_strings();
    ERR_load_BUF_strings();
    ERR_load_CRYPTO_strings();
    ERR_load_EC_strings();
    ERR_load_ERR_strings();
    ERR_load_EVP_strings();
    ERR_load_RAND_strings();
}

void Global_Initialize(){
    bn_ctx = BN_CTX_new();

    if (bn_ctx == nullptr) std::cerr << "bn_ctx initialize fails" << std::endl;
    #ifdef PARALLEL
        ec_ctx = nullptr;
    #else
        if(thread_count > 1){
            std::cerr << "parallel parameter setting is wrong" << std::endl;
            exit(1); 
        }
        ec_ctx = bn_ctx; 
    #endif

    // initialize fixed aes key
    block salt = Block::zero_block;
    fix_aes_enc_key = AES::GenEncKey(salt); 
    fix_aes_dec_key = AES::DeriveDecKeyFromEncKey(fix_aes_enc_key); 

}

void Global_Finalize(){
    BN_CTX_free(bn_ctx);
} 

#endif
