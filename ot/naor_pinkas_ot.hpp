/*
** Modified from the following project
** 1. https://github.com/emp-ot/
*/

#ifndef KUNLUN_IO_NPOT_HPP__
#define KUNLUN_IO_NPOT_HPP__

#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/block.hpp"
#include "../io/net_io_stream_channel.hpp"

/*
 * Noar Pinkas OT
 * [REF] Implementation of "Efficient Oblivious Transfer Protocols"
 * https://dl.acm.org/doi/10.5555/365411.365502
*/

namespace NPOT{

struct PP
{
	ECPoint g;
};

void Setup(PP &pp)
{
	pp.g = ECPoint(generator); 
}

void Send(NetIO &io, PP &pp, const std::vector<block>& vec_m0, const std::vector<block> &vec_m1, size_t LEN)
{
	if(vec_m0.size()!=LEN || vec_m1.size()!=LEN){
		std::cerr << "size does not match" << std::endl; 
	} 

	std::vector<BigInt> vec_r(LEN); // randomness used for encryption
	std::vector<ECPoint> vec_pk0(LEN);

	std::vector<ECPoint> vec_X(LEN); // the first ciphertext component 
	std::vector<ECPoint> vec_Z(LEN); // the initial form of second ciphertext component 

	// offline process
	BigInt d = GenRandomBigIntLessThan(order);
	ECPoint C = pp.g * d;  // compute C = g^d

	//  compute g^r[i] and C^r[i]
	for(auto i = 0; i < LEN; i++) {
		vec_r[i] = GenRandomBigIntLessThan(order);
		vec_X[i] = pp.g * vec_r[i];
		vec_Z[i] = C * vec_r[i];
	}

	// send C
	io.SendECPoints(&C, 1);
	io.SendECPoints(vec_X.data(), LEN); 

	io.ReceiveECPoints(vec_pk0.data(), LEN); 

	std::vector<ECPoint> vec_K0(LEN); // session key
	std::vector<ECPoint> vec_K1(LEN); // session key
	std::vector<block> vec_Y0(LEN);  
	std::vector<block> vec_Y1(LEN); 

	// send m0 and m1
	#ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
	for(auto i = 0 ; i < LEN; ++i) {
		vec_K0[i] = vec_pk0[i] * vec_r[i];
		vec_K1[i] = vec_Z[i] - vec_K0[i];
		vec_Y0[i] = Hash::ECPointToBlock(vec_K0[i]) ^ vec_m0[i];
		vec_Y1[i] = Hash::ECPointToBlock(vec_K1[i]) ^ vec_m1[i];
	}
	io.SendBlocks(vec_Y0.data(), LEN);
	io.SendBlocks(vec_Y1.data(), LEN);
}

void Receive(NetIO &io, PP &pp, std::vector<block> &vec_result, const std::vector<uint8_t> &vec_selection_bit, size_t LEN)
{
	if(vec_result.size()!=LEN || vec_selection_bit.size()!=LEN){
		std::cerr << "size does not match" << std::endl; 
	}

	std::vector<BigInt> vec_sk(LEN);
	std::vector<ECPoint> vec_X(LEN); 
	std::vector<ECPoint> vec_pk0(LEN);

    #ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
	for(auto i = 0; i < LEN; i++){
		vec_sk[i] = GenRandomBigIntLessThan(order);
	}
	
	ECPoint C; 	
	io.ReceiveECPoints(&C, 1); 
	io.ReceiveECPoints(vec_X.data(), LEN);

	// send pk0[i]
	#ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
	for(auto i = 0; i < LEN; i++) {
		if(vec_selection_bit[i] == 1){
			vec_pk0[i] = C - pp.g * vec_sk[i]; 
		} else {
			vec_pk0[i] = pp.g * vec_sk[i];
		}
	}
	io.SendECPoints(vec_pk0.data(), LEN);

	// compute Kb[i]
	std::vector<ECPoint> vec_K(LEN); 
	std::vector<block> vec_Y0(LEN); 
	std::vector<block> vec_Y1(LEN); 

	io.ReceiveBlocks(vec_Y0.data(), LEN);
	io.ReceiveBlocks(vec_Y1.data(), LEN); 

    #ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
	for(auto i = 0; i < LEN; i++)
	{
		vec_K[i] = vec_X[i]* vec_sk[i];
	}


	// decrypt with Kb[i]
    #ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
	for(auto i = 0; i < LEN; i++) {
		if(vec_selection_bit[i] == 0) vec_result[i] = vec_Y0[i] ^ Hash::ECPointToBlock(vec_K[i]);
		else vec_result[i] = vec_Y1[i] ^ Hash::ECPointToBlock(vec_K[i]);
	}
}
}
#endif
