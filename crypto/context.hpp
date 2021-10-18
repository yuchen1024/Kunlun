#ifndef CRYPTO_CONTEXT_HPP_
#define CRYPTO_CONTEXT_HPP_

#include "std.inc"
#include "openssl.inc"


// this define means every implementation should be thread safe w.r.t. bn_ctx
//#define THREAD_SAFE

static size_t BN_BYTE_LEN;  // the byte length of bigint
static size_t FIELD_BYTE_LEN;  // each scalar field element is 256 bit 
static size_t INT_BYTE_LEN;   // the byte length of built-in size_t

static BN_CTX *bn_ctx; 
// EVP_MD_CTX *evp_md_ctx;  
// HMAC_CTX *hmac_ctx;

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

void Context_Initialize(){
    bn_ctx = BN_CTX_new();
    if (bn_ctx == nullptr) std::cerr << "bn_ctx initialize fails" << std::endl;
    // evp_md_ctx = EVP_MD_CTX_create(); 
    // if (evp_md_ctx == nullptr) std::cerr << "evp_md_ctx initialize fails" << std::endl;
    // hmac_ctx = HMAC_CTX_new();
    // if (hmac_ctx == nullptr) std::cerr << "hmac_ctx initialize fails" << std::endl;
}

void Context_Finalize(){
    BN_CTX_free(bn_ctx);
    // EVP_MD_CTX_destroy(evp_md_ctx);
    // HMAC_CTX_free(hmac_ctx);
} 


#endif  // CONTEXT_HPP_













