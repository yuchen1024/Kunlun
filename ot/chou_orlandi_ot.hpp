#ifndef KUNLUN_CO_OT_HPP_
#define KUNLUN_CO_OT_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../io/net_io_channel.hpp"

/*
 * Chou Orlandi OT
 * [REF] Implementation of "The Simplest Protocol for Oblivious Transfer"
 * https://eprint.iacr.org/2015/267.pdf
 */


struct CO_OT_PP
{
    ECPoint g;
};

void CO_OT_Setup(NP_OT_PP &pp)
{
    pp.g = ECPoint(generator); 
}

void CO_OT_Send(NetIO &io, CO_OT_PP &pp, const std::vector<block>& vec_m0, const std::vector<block> &vec_m1)
{
    size_t LEN = vec_m0.size(); 

    BigInt a = GenRandomBigIntLessThan(order);
    ECPoint A = pp.g * a;
    io.Send_ECPoint(A);
    ECPoint_Aa = A * a;

    std::vector<ECPoint> vec_B(LEN); 
    io.Receive_ECPoints(vec_B);

    std::vector<ECPoint> vec_K0(LEN); // session key
    std::vector<ECPoint> vec_K1(LEN); // session key

    std::vector<block> vec_Y0(LEN);  
    std::vector<block> vec_Y1(LEN); 

    // send m0 and m1
    for(auto i = 0 ; i < LEN; ++i) {
        vec_K0[i] = vec_B[i] * a;
        vec_K1[i] = vec_Z0[i] - Aa;
        vec_Y0[i] = HashECPointToBlock(vec_K0[i]) ^ vec_m0[i];
        vec_Y1[i] = HashECPointToBlock(vec_K1[i]) ^ vec_m1[i];
    }
    io.Send_Blocks(vec_Y0.data(), LEN);
    io.Send_Blocks(vec_Y1.data(), LEN);
}


void CO_OT_Receive(NetIO &io, CO_OT_PP &pp, std::vector<block> &vec_result, const std::vector<bool> &vec_selection_bit)
{
    size_t LEN = vec_result.size(); 

    std::vector<ECPoint> vec_B(LEN); 
    std::vector<BigInt> vec_b(LEN); 

    ECPoint A;
    io.Receive_Point(A);

    for(auto i = 0; i < LEN; ++i) {
        vec_b[i] = GenRandomBigIntLessThan(order); 
        vec_B[i] = pp.g * vec_b[i];
        if (b[i] == 1) {
            vec_B[i] = vec_B[i] + A;
        }
    }
    io.Send_ECPoints(vec_B); 


    std::vector<block> vec_Y0(LEN); 
    std::vector<block> vec_Y1(LEN); 
    io.Receive_Blocks(vec_Y0.data(), LEN);
    io.Receive_Blocks(vec_Y1.data(), LEN); 

    ECPoint vec_K(LEN); 
    for(auto i = 0; i < LEN; i++){
        vec_K[i] = A * vec_b[i];
        if(vec_selection_bit[i] == 0){
            vec_result[i] = vec_Y0[i] ^ HashECPointToBlock(vec_K[i]);
        }
        else {
            vec_result[i] = vec_Y1[i] ^ HashECPointToBlock(vec_K[i]);
        } 
    }
}            

#endif// OT_CO_H__
