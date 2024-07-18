/****************************************************************************
this hpp file define and initialize misc global variables 
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_SETUP_HPP_
#define KUNLUN_SETUP_HPP_

#include "../include/std.inc"
#include "../include/openssl.inc"
#include "../utility/print.hpp"

#include "bigint.hpp"
#include "ec_group.hpp"
#include "hash.hpp"
#include "prg.hpp"
#include "block.hpp"
#include "aes.hpp"

void CRYPTO_Initialize()
{
    BN_Initialize();
    ECGroup_Initialize(); 
    AES_Initialize();   // does not need Finalize() 

    /* 
    * set number of threads to ensure thread_number obtained via omp_get_thread_no() lies in [0, NUMBER_OF_THREADS)  
    * otherwise segmentation fault may occur when a thread i attempts to access bn_ctx[i], whose memory is not allocated
    */
    omp_set_num_threads(NUMBER_OF_THREADS); 

    PrintSplitLine('-'); 
    std::cout << "GLOBAL ENVIROMENT INFO >>>" << std::endl;
    std::cout << "NUM OF THREADS = " << NUMBER_OF_THREADS << std::endl;

    std::cout << "EC Curve ID = " << curve_id << std::endl;
    std::cout << "ECPoint COMPRESSION = "; 
    #ifdef ECPOINT_COMPRESSED
        std::cout << "ON" << std::endl;
    #else
        std::cout << "OFF" << std::endl;
    #endif
    
    #ifdef ENABLE_X25519_ACCELERATION
        PrintSplitLine('-');  
        std::cout << "Accelerate ***somewhat*** EC exponentiation using x25519 method powerd by Curve25519 >>>" << std::endl; 
    #endif

    PrintSplitLine('-');  
}

void CRYPTO_Finalize()
{
    BN_Finalize();
    ECGroup_Finalize();
} 

#endif
