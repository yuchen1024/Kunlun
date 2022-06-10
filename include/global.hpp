/****************************************************************************
this hpp file define global variables for the Kunlun lib 
thread_count indicates the maximum number of threads that openmp works
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_GLOBAL_HPP_
#define KUNLUN_GLOBAL_HPP_

#include "openssl.inc"
#include "std.inc"

#define PARALLEL
const static size_t thread_count = 8; // maximum thread count 

const static size_t CHECK_BUFFER_SIZE = 1024*8;

// return the error message reported by OpenSSL
void CRYPTO_CHECK(bool condition)
{
    if (condition == false){
        char buffer[256];
        ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
        std::cerr << std::string(buffer);
    }
} 

void LoadErrorStrings()
{
    ERR_load_BN_strings();
    ERR_load_BUF_strings();
    ERR_load_CRYPTO_strings();
    ERR_load_EC_strings();
    ERR_load_ERR_strings();
    ERR_load_EVP_strings();
    ERR_load_RAND_strings();
}


#endif
