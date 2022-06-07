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

#include "bigint.hpp"
#include "ec_group.hpp"
#include "hash.hpp"
#include "prg.hpp"
#include "block.hpp"
#include "aes.hpp"

void CRYPTO_Initialize(){
    BN_Initialize();
    ECGroup_Initialize(); 
    AES_Initialize();
}

void CRYPTO_Finalize(){
    BN_Finalize();
    ECGroup_Finalize();
} 

#endif
