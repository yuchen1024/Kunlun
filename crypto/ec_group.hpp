#ifndef CRYPTO_EC_GROUP_HPP_
#define CRYPTO_EC_GROUP_HPP_

#include "openssl.inc"
#include "context.hpp"

static EC_GROUP *group;
const static EC_POINT *generator; 

static BIGNUM *order;
static BIGNUM *cofactor;  // The cofactor of this group
static BIGNUM *curve_params_p; 
static BIGNUM *curve_params_a; 
static BIGNUM *curve_params_b;
static BIGNUM *curve_params_q; // q = (p-1)/2

static size_t POINT_LEN; // the byte length of ec point in compressed form

void ECGroup_Initialize(int curve_id){
    group = EC_GROUP_new_by_curve_name(curve_id);
    // If this fails, this is usually due to an invalid curve id.
    if (group == nullptr) {
        std::cerr << "EC Group: Could not create group." << OpenSSLErrorString();
    }

    generator = EC_GROUP_get0_generator(group);

    order = BN_new(); 
    if (EC_GROUP_get_order(group, order, bn_ctx) != 1) {
        std::cerr << "EC Group: Could not get order." << OpenSSLErrorString();
    }

    cofactor = BN_new(); 
    if (EC_GROUP_get_cofactor(group, cofactor, bn_ctx) != 1) {
        std::cerr << "ECGroup: Could not get cofactor." << OpenSSLErrorString();
    }

    curve_params_p = BN_new(); 
    curve_params_a = BN_new();
    curve_params_b = BN_new(); 
    if (EC_GROUP_get_curve_GFp(group, curve_params_p, curve_params_a, curve_params_b, bn_ctx) != 1) {
        std::cerr << "ECGroup: Could not get params." << OpenSSLErrorString();
    }

    size_t rounds = 100; 
    if(BN_is_prime_ex(curve_params_p, rounds, bn_ctx, nullptr) == 0) {
        std::cerr << "ECGroup: p is not prime." << OpenSSLErrorString();
    }

    curve_params_q = BN_new(); 
    BN_rshift(curve_params_q, curve_params_p, 1); // p_minus_one_over_two = (p-1)/2

    BN_LEN = BN_num_bits(curve_params_p);
    BN_LEN = BN_LEN/8+BN_LEN%8;
    POINT_LEN = BN_LEN + 1; 

    BIT_SIZE = BN_LEN * 8; 
    INT_LEN = sizeof(size_t); 

    EC_GROUP_precompute_mult((EC_GROUP*) group, bn_ctx); // pre-compute the table of g     
    
    #ifdef DEBUG
    if(EC_GROUP_have_precompute_mult((EC_GROUP*) group)){ 
        std::cout << "precompute enable" << std::endl;
    } 
    else{
        std::cout << "precompute disable" << std::endl;
    } 
    #endif
}

void ECGroup_Finalize(){
    EC_GROUP_free(group);
    
    BN_free(curve_params_p); 
    BN_free(curve_params_a); 
    BN_free(curve_params_b);
    BN_free(curve_params_q); 

    BN_free(order); 
    BN_free(cofactor); 
}

#endif //_CRYPTO_EC_GROUP_HPP_







