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
    AES_Initialize();
    #ifdef PARALLEL
    if(thread_count == 1){
        std::cerr << "parallel parameter setting is wrong" << std::endl;
    }
    #endif

    PrintSplitLine('-'); 
    std::cout << "ENVIROMENT INFO >>>" << std::endl;
    std::cout << "THREAD NUM = " << thread_count << std::endl;
    std::cout << "ECPoint COMPRESSION = "; 
    #ifdef ECPOINT_COMPRESSED
        std::cout << "ON" << std::endl;
    #else
        std::cout << "OFF" << std::endl;
    #endif
    PrintSplitLine('-');  

}

void CRYPTO_Finalize()
{
    BN_Finalize();
    ECGroup_Finalize();
} 

#endif
