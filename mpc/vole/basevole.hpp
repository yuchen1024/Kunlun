
/** @file
*****************************************************************************
This is an implementation of baseVOLE.
In detail, we implement the protocol in Figure:15 with p = p^r = 2^128.

 References:
 \[WYKW21]: 
 "Wolverine: Fast, Scalable, and Communication-Efficient Zero-Knowledge Proofs for Boolean and Arithmetic Circuits",
 Chenkai Weng, Kang Yang, Jonathan Katz, and Xiao Wang, 
 IEEE Symposium on Security and Privacy (Oakland), 2021
 <https://eprint.iacr.org/2020/925>


 *****************************************************************************
 * @author     developed by Yujie Bai (with help of Weiran Liu)
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef BASEVOLE_HPP
#define BASEVOLE_HPP
#include <vector>
#include <iostream>
#include "../ot/alsz_ote.hpp"
#include "../../crypto/aes.hpp"
#include"../../crypto/block.hpp"


namespace VOLE {
	// In the beginning, A holds u and B holds delta.
	//In the end, A obtains w and B obtains v, satisfying w = v + u*delta.
	
	// call baseVOLE once
	std::vector<block> baseVOLE_A(NetIO &io,block* ptr_u = nullptr);
	std::vector<block> baseVOLE_B(NetIO &io,block* ptr_delta = nullptr);
	
	// call baseVOLE t times
	void baseVOLE_tA(NetIO &io, uint64_t t, std::vector<block>& vec_u, std::vector<block>& vec_w);
	void baseVOLE_tB(NetIO &io, uint64_t t, std::vector<block>& vec_v, block delta);
	
	
	inline block gf128_mul(const block x, const block y);
	// <g,vec_x> = gf128_mul(2^0,vec_x[0])+...+gf128_mul(2^127,vec_x[127])
	inline block gadget_innerProduct(std::vector<block> vec_x);
	

	// return [u, w = share_(U*delta)]
	std::vector<block> baseVOLE_A(NetIO &io, block* ptr_u){

		// set fixed seed for PRG 
		PRG::Seed prg_seed = PRG::SetSeed(fixed_seed, 0);	
			
		// set a random seed to sample 128 pairs of random K0, K1 
		PRG::Seed seed_k = PRG::SetSeed();
		std::vector<block> vec_k0 = PRG::GenRandomBlocks(seed_k, 128);
		std::vector<block> vec_k1 = PRG::GenRandomBlocks(seed_k, 128);
		
		// send vec_k0,vec_k1 to OT 
		std::string pp_filename = "npot.pp";
		NPOT::PP pp; 
    		if(!FileExist(pp_filename)){
        		pp = NPOT::Setup(); 
        		NPOT::SavePP(pp, pp_filename); 
    		}
    		else{
        	 	NPOT::FetchPP(pp, pp_filename); 
    		}

		
		Send(io, pp, vec_k0, vec_k1, 128);
		
		
		// how to do the following in parallel
		std::vector<block> vec_w0(128);
		std::vector<block> vec_w1(128);

		AES::FastECBEnc(prg_seed.aes_key, vec_k0.data(), 128, vec_w0.data());
		AES::FastECBEnc(prg_seed.aes_key, vec_k1.data(), 128, vec_w1.data());
		
		// get u
		block u;
		// if there is no given u
		if(ptr_u == nullptr){
			u = PRG::GenRandomBlocks(seed_k, 1)[0];
		}
		else{
			u = _mm_loadu_si128(ptr_u);
		}
	
		// calculate vec_gama
		std::vector<block> vec_gama(128);
		for(auto i = 0; i < 128; i+=8){
			vec_gama[i] = vec_w0[i] ^ vec_w1[i] ^ u;
			vec_gama[i+1] = vec_w0[i+1] ^ vec_w1[i+1] ^ u;
			vec_gama[i+2] = vec_w0[i+2] ^ vec_w1[i+2] ^ u;
			vec_gama[i+3] = vec_w0[i+3] ^ vec_w1[i+3] ^ u;
			vec_gama[i+4] = vec_w0[i+4] ^ vec_w1[i+4] ^ u;
			vec_gama[i+5] = vec_w0[i+5] ^ vec_w1[i+5] ^ u;
			vec_gama[i+6] = vec_w0[i+6] ^ vec_w1[i+6] ^ u;
			vec_gama[i+7] = vec_w0[i+7] ^ vec_w1[i+7] ^ u;						
		}
		
		// send vec_gama to B		
		
		io.SendBlocks(vec_gama.data(),128);
		
		// calculate <g,w0> 
		block w = gadget_innerProduct(vec_w0);
		
		std::vector<block> res(2);
		res[0] = u;
		res[1] = w;
		return res;
	
	}
	
	// return [delta, v = share_(u*delta)]
	std::vector<block> baseVOLE_B(NetIO &io,block* ptr_delta){
		block delta;
		// if there is no given delta
		if(ptr_delta == nullptr){
			//set a random seed to sample delta
			PRG::Seed seed_delta = PRG::SetSeed();
			delta = PRG::GenRandomBlocks(seed_delta, 1)[0];
			
		}
		else{
			delta = _mm_loadu_si128(ptr_delta);
		}
		
		// decompose delta into vec_delta_bit and delta = (u64_h, u64_l)
		std::vector<uint8_t> vec_delta_bit(128);
		uint64_t u64_l,u64_h;
		uint64_t * p = (uint64_t*) &delta;
		u64_l = p[0];
		u64_h = p[1];
		for(auto i = 0; i<128;++i){
			if(i<64){
				if(u64_l % 2==1){
					vec_delta_bit[i] = 1;
				}
				else{
					vec_delta_bit[i] = 0;
				}
				u64_l >>= 1;	
			}
			else{
				if(u64_h % 2==1){
					vec_delta_bit[i] = 1;
				}
				else{
					vec_delta_bit[i] = 0;
				}
				u64_h >>= 1;
			}
		}

		// use vec_delta_bit to receive 128 K from OT 
		std::string pp_filename = "npot.pp";
		NPOT::PP pp;
    		if(!FileExist(pp_filename)){
        		pp = NPOT::Setup(); 
        		NPOT::SavePP(pp, pp_filename); 
    		}
    		else{
        		NPOT::FetchPP(pp, pp_filename); 
    		}
		
		std::vector<block> vec_k = Receive(io, pp, vec_delta_bit, 128);
		
		// set fixed seed for PRG 
		PRG::Seed prg_seed = PRG::SetSeed(fixed_seed, 0);
		
		//calculate vec_w = PRF(w)
		std::vector<block> vec_w(128);
		AES::FastECBEnc(prg_seed.aes_key, vec_k.data(), 128, vec_w.data());
	
		// receive vec_gama from A
		std::vector<block> vec_gama(128);
		io.ReceiveBlocks(vec_gama.data(),128);
		
		// calculate vec_v = vec_w + vec_delta_bit * vec_gama
		std::vector<block> vec_v(128);
		for(auto i = 0;i < 128; ++i){
			if(vec_delta_bit[i] == 1){
				vec_v[i] = vec_w[i] ^ vec_gama[i];
			}
			else{
				vec_v[i] = vec_w[i];
			}
		}
		
		// calculate <g,vec_v>
		block v = gadget_innerProduct(vec_v);		
		std::vector<block> res(2);
		res[0] = delta;
		res[1] = v;
		return res;		
	}
	
	

	// return [u, w = share_(U*delta)]
	void baseVOLE_tA(NetIO &server_io, uint64_t t, std::vector<block>& vec_u, std::vector<block>& vec_w){
		vec_u.resize(t);
		vec_w.resize(t);
		uint64_t BASE_LEN = 128;
		uint64_t EXTEND_LEN = t * 128;
		
		// set fixed seed for PRG 
		PRG::Seed prg_seed = PRG::SetSeed(fixed_seed, 0);	
			
		// set a random seed to sample 128 pairs of random K0, K1 
		PRG::Seed seed_k = PRG::SetSeed();
		std::vector<block> vec_k0 = PRG::GenRandomBlocks(seed_k, EXTEND_LEN);
		std::vector<block> vec_k1 = PRG::GenRandomBlocks(seed_k, EXTEND_LEN);
		
		// send vec_k0,vec_k1 to OT 
		ALSZOTE::PP pp;
		std::string pp_filename = "alszote.pp"; 
    		if(!FileExist(pp_filename)){
        		pp = ALSZOTE::Setup(BASE_LEN); 
        		ALSZOTE::SavePP(pp, pp_filename); 
    		}
    		else{
        		ALSZOTE::FetchPP(pp, pp_filename);
    		}

		
		ALSZOTE::Send(server_io, pp, vec_k0, vec_k1, EXTEND_LEN);
		
		
		// how to do the following in parallel
		std::vector<block> vec_w0(EXTEND_LEN);
		std::vector<block> vec_w1(EXTEND_LEN);

		AES::FastECBEnc(prg_seed.aes_key, vec_k0.data(), EXTEND_LEN, vec_w0.data());
		AES::FastECBEnc(prg_seed.aes_key, vec_k1.data(), EXTEND_LEN, vec_w1.data());
		
		// there is no given u
		vec_u = PRG::GenRandomBlocks(seed_k, t);

		
		// calculate vec_gama
		std::vector<block> vec_gama(EXTEND_LEN);
		for(auto j = 0; j < t; ++j){
			for(auto i = 0; i < 128; i+=8){
				auto temp = j*128 + i;
				vec_gama[temp] = vec_w0[temp] ^ vec_w1[temp] ^ vec_u[j];
				vec_gama[temp+1] = vec_w0[temp+1] ^ vec_w1[temp+1] ^ vec_u[j];
				vec_gama[temp+2] = vec_w0[temp+2] ^ vec_w1[temp+2] ^ vec_u[j];
				vec_gama[temp+3] = vec_w0[temp+3] ^ vec_w1[temp+3] ^ vec_u[j];
				vec_gama[temp+4] = vec_w0[temp+4] ^ vec_w1[temp+4] ^ vec_u[j];
				vec_gama[temp+5] = vec_w0[temp+5] ^ vec_w1[temp+5] ^ vec_u[j];
				vec_gama[temp+6] = vec_w0[temp+6] ^ vec_w1[temp+6] ^ vec_u[j];
				vec_gama[temp+7] = vec_w0[temp+7] ^ vec_w1[temp+7] ^ vec_u[j];						
			}
		}
		
		// send vec_gama to B		
		server_io.SendBlocks(vec_gama.data(),EXTEND_LEN);
		
		// calculate <g,w0> 
		for(auto i = 0; i < t; ++i){
			auto begin = vec_w0.begin() + (i*128);
			std::vector<block> temp_vec_w0(begin, begin+128);
			vec_w[i] = gadget_innerProduct(temp_vec_w0);
		}

	}
	
	// return delta, [v = share_(u*delta)]
	void baseVOLE_tB(NetIO &client_io, uint64_t t, std::vector<block>& vec_v, block delta){
		vec_v.resize(t);
		
		uint64_t BASE_LEN = 128;
		uint64_t EXTEND_LEN = t * 128;
			
		// decompose delta into vec_delta_bit and delta = (u64_h, u64_l)
		std::vector<uint8_t> vec_delta_bit(BASE_LEN);
		// vec_select_bit = t * vec_delta_bit 
		std::vector<uint8_t> vec_select_bit(EXTEND_LEN);
		uint64_t u64_l,u64_h;
		uint64_t * p = (uint64_t*) &delta;
		u64_l = p[0];
		u64_h = p[1];
		for(auto i = 0; i < 128;++i){
			if(i<64){
				if(u64_l % 2==1){
					vec_delta_bit[i] = 1;
					for(auto j = 0; j < t; ++j){
						vec_select_bit[j*128 + i] = 1;
					}
				}
				u64_l >>= 1;	
			}
			else{
				if(u64_h % 2==1){
					vec_delta_bit[i] = 1;
					for(auto j = 0; j < t; ++j){
						vec_select_bit[j*128 + i] = 1;
					}
				}
				u64_h >>= 1;
			}
		}

		// use vec_delta_bit to receive 128 K from OT 
		ALSZOTE::PP pp;
		std::string pp_filename = "alszote.pp"; 
    		if(!FileExist(pp_filename)){
        		pp = ALSZOTE::Setup(BASE_LEN); 
        		ALSZOTE::SavePP(pp, pp_filename); 
    		}
    		else{
        		ALSZOTE::FetchPP(pp, pp_filename);
    		}
		std::vector<block> vec_k = ALSZOTE::Receive(client_io, pp, vec_select_bit, EXTEND_LEN);
		
		// set fixed seed for PRG 
		PRG::Seed prg_seed = PRG::SetSeed(fixed_seed, 0);
		
		//calculate vec_w = PRF(w)
		std::vector<block> vec_w(EXTEND_LEN);
		AES::FastECBEnc(prg_seed.aes_key, vec_k.data(), EXTEND_LEN, vec_w.data());
	
		// receive vec_gama from A
		std::vector<block> vec_gama(EXTEND_LEN);
		client_io.ReceiveBlocks(vec_gama.data(),EXTEND_LEN);
		
		// calculate vec_v = vec_w + vec_delta_bit * vec_gama
		std::vector<block> temp_vec_v(128);
		for(auto j = 0;j < t; j++){
			auto temp = j * 128;
			for(auto i = 0;i < 128; ++i){
				if(vec_delta_bit[i] == 1){
					temp_vec_v[i] = vec_w[i+temp] ^ vec_gama[i+temp];
				}
				else{
					temp_vec_v[i] = vec_w[i+temp];
				}
			}
			// calculate <g,temp_vec_v>
			vec_v[j] = gadget_innerProduct(temp_vec_v);
		}
	}


	
	__attribute__((target("pclmul,sse2")))
	inline block gf128_mul(const block x, const block y)
	{

  	  block x0y0 = _mm_clmulepi64_si128(x, y, 0x00);
  	  block x1y0 = _mm_clmulepi64_si128(x, y, 0x10);
  	  block x0y1 = _mm_clmulepi64_si128(x, y, 0x01);
  	  block x1y1 = _mm_clmulepi64_si128(x, y, 0x11);
  	  x1y0 = (x1y0 ^ x0y1);
  	  x0y1 = _mm_slli_si128(x1y0, 8);
   	  x1y0 = _mm_srli_si128(x1y0, 8);
   	  x0y0 = (x0y0 ^ x0y1);
   	  x1y1 = (x1y1 ^ x1y0);

   	  auto mul256_low = x0y0;
   	  auto mul256_high = x1y1;

   	  static const constexpr std::uint64_t mod_omit128 = 0b10000111;

  	  const block modulus_omit128 = _mm_loadl_epi64((const block *)&(mod_omit128));
  	  block impact = _mm_clmulepi64_si128(mul256_high, modulus_omit128, 0x01);
   	  mul256_low = _mm_xor_si128(mul256_low, _mm_slli_si128(impact, 8));
   	  mul256_high = _mm_xor_si128(mul256_high, _mm_srli_si128(impact, 8));

    	  impact = _mm_clmulepi64_si128(mul256_high, modulus_omit128, 0x00);
   	  mul256_low = _mm_xor_si128(mul256_low, impact);

    	  return mul256_low;
	}
	// calculate <g,vec_x> = gf128_mul(2^0,vec_x[0])+...+gf128_mul(2^127,vec_x[127])
	inline block gadget_innerProduct(std::vector<block> vec_x){
		assert(vec_x.size() == 128);
		block x = _mm_set_epi64x(0LL, 0ll);
		for(auto i = 0; i < 128; ++i){
			block wi;
			if(i<64){
				wi = _mm_set_epi64x(0LL, 1LL << i);
			}
			else{
				wi = _mm_set_epi64x(1LL << (i-64), 0LL);
			}
			x ^= gf128_mul(wi, vec_x[i]);
		}
		return x;
	}
	
	
}
#endif
