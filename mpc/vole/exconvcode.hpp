/** @file
*****************************************************************************
This is an implementation of Expand-Convolute Code.
G * x = BC * x
G:{0,1}k×n  B:{0,1}k×n  C:{0,1}n×n
dualEncode(vec_x) = expand(accumulate(vec_x))

 References:
 \[RRT23]: 
 "Expand-Convolute Codes for Pseudorandom Correlation Generators from LPN",
 Srinivasan Raghuraman, Peter Rindal and Titouan Tanguy 
 CRYPTO 2023
 <https://eprint.iacr.org/2023/882>


 *****************************************************************************
 * @author     developed by Yujie Bai (with help of Weiran Liu)
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef EXCONVCODE_HPP
#define EXCONVCODE_HPP
#include <vector>
#include<iostream>
#include<string.h>
#include <assert.h>
#include"../../crypto/block.hpp"
#include"../../crypto/prg.hpp"

namespace VOLE {
	std::vector<uint32_t> GenRandomMod(uint32_t mmod, uint32_t len, PRG::Seed seed = PRG::SetSeed());

	class ExConvCode {
	private:
		uint32_t messageSize;// k
		uint32_t codeSize;// n
		PRG::Seed mSeed;
		uint32_t R; // R = codeSize / messageSize
		uint32_t expanderWeight;
		uint32_t accumulatorSize;
	public:
		void config(PRG::Seed seed, uint32_t mR = 2, uint32_t mExpanderWeight = 21, uint32_t mAccumulatorSize = 24);

		// e[0,1...,k-1] = G * e 
		
		// dualEncode(vec_x) = expand(accumulate(vec_x))
		void dualEncode(std::vector<block> &e);
		void dualEncode2(std::vector<block> &e0, std::vector<block> &e1);

		void accumulate(std::vector<block> &x);
		void accumulate2(std::vector<block> &x0, std::vector<block> &x1);

		
		void expand(std::vector<block> const e, std::vector<block> &w);
		void expand2(std::vector<block> const e1, std::vector<block> const e2, std::vector<block> &w1, std::vector<block> &w2);

	};

	std::vector<uint32_t> GenRandomMod(uint32_t mmod, uint32_t len, PRG::Seed seed) {
		std::vector<uint32_t> vec_b(len);
		uint32_t BLOCK_LEN = len / 4 + 1;
		std::vector<block> vec_a;
		PRG::Seed mSeed;
		mSeed.counter = seed.counter;
		mSeed.aes_key = seed.aes_key;
		vec_a = PRG::GenRandomBlocks(mSeed, BLOCK_LEN);

		auto LEN = len * (sizeof(uint32_t));
		memcpy(vec_b.data(), vec_a.data(), LEN);
		for (uint32_t i = 0; i < len; ++i) {
			vec_b[i] = vec_b[i] % mmod;
		}
		return vec_b;
	}

	void ExConvCode::config(PRG::Seed seed, uint32_t mR, uint32_t mExpanderWeight, uint32_t mAccumulatorSize) {
		// we can set the value of R, R = codeSize / messageSize
		R = mR;
		expanderWeight = mExpanderWeight;
		accumulatorSize = mAccumulatorSize;
		mSeed.counter = seed.counter;
		mSeed.aes_key = seed.aes_key;
		
	}

	// e[0,1...,k-1] = G * e
	void ExConvCode::dualEncode(std::vector<block>& e) {
		// we can set the value of R, R = codeSize / messageSize
		codeSize = e.size();
		messageSize = codeSize / R;

		// d[1,2...,n] = accumulate(e[1,2,...,n])
		std::vector<block> d(e.begin(), e.end());
		accumulate(d);

		// e is just a volume for d to expand
		e.resize(messageSize);

		//e[0,1...,k-1] is the final output
		expand(d, e);
		

	}

	void ExConvCode::dualEncode2(std::vector<block>& e0, std::vector<block>& e1) {
		assert(e0.size() == e1.size());
		codeSize = e0.size();
		messageSize = codeSize / R;

		// d[0,1,...,n-1] = accumulate(e[0,1,...,n-1])
		std::vector<block> d0(e0.begin(), e0.end());
		std::vector<block> d1(e1.begin(), e1.end());
		accumulate2(d0, d1);

		// e is just a volume for d to expand
		e0.resize(messageSize);
		e1.resize(messageSize);

		//e[1, 2..., k] is the final output
		expand2(d0, d1, e0, e1);
	}

	// accumulate x on itself
	void ExConvCode::accumulate(std::vector<block>& x) {
		uint32_t i = 0;
		uint32_t j;
		uint32_t size = x.size();

		std::vector<uint8_t> rnd = PRG::GenRandomBits(mSeed, size * accumulatorSize);
		auto main = (uint32_t)std::max<int32_t>(0, size - accumulatorSize);
		uint8_t* __restrict rrnd = rnd.data();
		
		for (; i < main; ++i) {
			j = i + 1;
			for (auto jj = 0; jj < accumulatorSize-1; ++jj, ++j, ++rrnd) {
				if (*rrnd == 1) {
					x[j] ^= x[i];
				}
			}
			// x[i+accumulatorSize] ^= x[i];
			// if (wrapping){  
			x[j] ^= x[i];
			// }
		}
		
		for (; i < size; ++i) {
			j = i + 1;
			auto temp_num = size-j;
			for (auto jj = 0; jj < temp_num; ++jj, ++j, ++rrnd) {
				if(*rrnd == 1){
					x[j] ^= x[i];
				}
			}
		}
	}


	void ExConvCode::accumulate2(std::vector<block>& x0, std::vector<block>& x1) {
		uint32_t i = 0;
		uint32_t j;
		uint32_t size = x0.size();

		// generate n alpha_i for convolution; alpha_i.size < = accumulatorSize; 
		std::vector<uint8_t> rnd = PRG::GenRandomBits(mSeed, size * accumulatorSize);
		uint8_t* __restrict rrnd = rnd.data();
		auto main = (uint32_t)std::max<int64_t>(0, size - accumulatorSize);
		
		for (; i < main; ++i) {
			j = i + 1;
			
			for (auto jj = 0; jj < accumulatorSize-1; ++jj, ++j, ++rrnd) {
				if (*rrnd == 1) {
					x0[j] ^= x0[i];
					x1[j] ^= x1[i];
				}
			}
			// set x[i+accumulatorSize] ^= x[i];
			// if (wrapping){
			x0[j] ^= x0[i];
			x1[j] ^= x1[i];
			// }
		}
		
		
		for (; i < size; ++i) {
			j = i + 1;
			auto temp_num = size-j;
			
			for (auto jj = 0; jj < temp_num; ++jj, ++j, ++rrnd) {
				if(*rrnd == 1){
					x0[j] ^= x0[i];
					x1[j] ^= x1[i];
				}
			}
		}
	}



	void ExConvCode::expand(std::vector<block> const e, std::vector<block>& w) {
		assert(e.size() == codeSize);
		assert(w.size() == messageSize);

		// generate messageSize * expanderWeight random positions in e[0,1,...,codeSize-1]
		std::vector<uint32_t> rnd = GenRandomMod(codeSize, messageSize * expanderWeight, mSeed);
		uint32_t* __restrict rrnd = rnd.data();

		for (auto i = 0; i < messageSize; ++i) {
			auto wv = e[*rrnd];
			++rrnd;
			for (auto jj = 1; jj < expanderWeight; ++jj, ++rrnd) {
				wv ^= e[*rrnd];
			}
			w[i] = wv;
		}
	}



	void ExConvCode::expand2(std::vector<block> const e1, std::vector<block> const e2, std::vector<block>& w1, std::vector<block>& w2) {
		assert(w1.size() == messageSize);
		assert(w2.size() == messageSize);
		assert(e1.size() == codeSize);
		assert(e2.size() == codeSize);

		// generate messageSize * expanderWeight random positions in e[0,1,...,codeSize-1]
		std::vector<uint32_t> rnd = GenRandomMod(codeSize, messageSize * expanderWeight, mSeed);
		uint32_t* __restrict rrnd = rnd.data();

		for (auto i = 0; i < messageSize; ++i) {
			auto wv1 = e1[*rrnd];
			auto wv2 = e2[*rrnd];
			++rrnd;
			for (auto jj = 1; jj < expanderWeight; ++jj, ++rrnd) {
				wv1 ^= e1[*rrnd];
				wv2 ^= e2[*rrnd];
			}
			w1[i] = wv1;
			w2[i] = wv2;
		}
	}



}




#endif
