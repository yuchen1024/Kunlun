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

    AES_Initialize();    
    #ifndef USING_CURVE_25519
        ECGroup_Initialize(); 
    #endif

    PrintSplitLine('-'); 
    std::cout << "GLOBAL ENVIROMENT INFO >>>" << std::endl;
    std::cout << "THREAD NUM = " << NUMBER_OF_THREADS << std::endl;
    #ifndef USING_CURVE_25519
        std::cout << "EC Curve ID = " << curve_id << std::endl;
        std::cout << "ECPoint COMPRESSION = "; 
        #ifdef ECPOINT_COMPRESSED
            std::cout << "ON" << std::endl;
        #else
            std::cout << "OFF" << std::endl;
        #endif
    #else
        std::cout << "EC Curve ID = 25519" << std::endl; 
    #endif
    PrintSplitLine('-');  

}

void CRYPTO_Finalize()
{
    BN_Finalize();
    #ifndef USING_CURVE_25519
        ECGroup_Finalize();
    #endif
} 

#endif
