
/** @file
*****************************************************************************
This is an implementation of single-point-VOLE(spVOLE) and t-multi-points-VOLE(t_mpVOLE).
Here we concatenate t spVOLE to get t_mpVOLE.

In detail, we implement the protocol in Figure:7 without consistency check.

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

#ifndef VOLE_HPP
#define VOLE_HPP
#include<cmath>
#include "../../crypto/setup.hpp"
#include"basevole.hpp"
#include"exconvcode.hpp"


namespace VOLE {

	//(1) VOLE = baseVOLE + tmpVOLE
	//A obtains vec_A and vec_C, B obtains vec_B and delta, satisfying vec_B = vec_C + vec_A*delta.
	std::vector<block> VOLE_A(NetIO &A_io, uint64_t N_item, std::vector<block>& vec_C, uint64_t t = 128);
	void VOLE_B(NetIO &B_io, uint64_t N_item, std::vector<block>& vec_B, block delta, uint64_t t = 128);
	
	
	// (2) tmpVOLE = t * spVOLE + ExConvCode
	void tmpVOLE_B(NetIO &B_io, uint64_t N_item, uint64_t t, std::vector<block> vec_v, std::vector<block>& vec_B);
	std::vector<block> tmpVOLE_A(NetIO& A_io, uint64_t N_item, uint64_t t, std::vector<block>& vec_C, std::vector<block> vec_u, std::vector<block> vec_w);
	
	block FullEval(uint8_t depth, block k, std::vector<block>& vec_leaf, std::vector<block>& vec_m0, std::vector<block>& vec_m1);
	std::vector<block> PuncEval(uint8_t depth, block beta, block* ptr_m, uint8_t* ptr_selection_bit);
	
	inline std::vector<block> GGM_PRG(block in);
	inline void TransToBitVec(uint64_t num, std::vector<uint8_t>& vec_bit, uint8_t LEN);
	
	
	
	/*  the range of t is [128,248]:
	** for:  t_max = std::max<uint64_t>(128, -double(secParam) / d);
	** d = std::log2(1 - 2 * minDistRatio);
	** in EC Code, we set a = 24, w = 21, minDistRatio = 0.15, secParam = 128;
	** so t_max = 248; 
	*/
	
	//(1) VOLE = baseVOLE + tmpVOLE
	//(1.1) return vec_A and vec_C
	std::vector<block> VOLE_A(NetIO &A_io, uint64_t N_item, std::vector<block>& vec_C, uint64_t t){
		std::vector<block> vec_u;
		std::vector<block> vec_w;
		std::vector<block> vec_A;
		
		// call baseVOLE to get vec_u and vec_w
		baseVOLE_tA(A_io, t, vec_u, vec_w);
		vec_A = tmpVOLE_A(A_io, N_item, t, vec_C, vec_u, vec_w);	
		return vec_A;
	
	}
	
	//(1.2) return vec_B
	void VOLE_B(NetIO &B_io, uint64_t N_item, std::vector<block>& vec_B, block delta, uint64_t t){
	 	std::vector<block> vec_v;		
		baseVOLE_tB(B_io, t, vec_v, delta);
		tmpVOLE_B(B_io, N_item, t, vec_v, vec_B);
		
	}
	
	
	
	//(2) tmpVOLE = t * spVOLE + ExConvCode
	//(2.1) return vec_B with input vec_v	
	void tmpVOLE_B(NetIO &server_io, uint64_t N_item, uint64_t t, std::vector<block> vec_v, std::vector<block>& vec_leaf) {
		if (!vec_leaf.empty()) {
			vec_leaf.clear();
		}
		N_item *= 2;// for EC Code mR=2
		uint64_t sub_len = N_item / t;
		uint64_t last_len = N_item % t + N_item / t;
		uint8_t level = (std::ceil(log2(sub_len)));
		uint8_t level_last1 = (std::ceil(log2(last_len)));
		uint64_t leaf_num = 1ull << level;
		uint64_t leaf_num_last1 = 1ull << level_last1;
		uint64_t selection_len = level * (t - 1) + level_last1;
		
		//generate t random blocks vec_k as root for GGM
		PRG::Seed seed_k = PRG::SetSeed();
		std::vector<block> vec_k = PRG::GenRandomBlocks(seed_k, t);
				
		// calculate send_to_R, vec_leaf, vec_m0, vec_m1 by FullEval()
		std::vector<block> vec_m0;
		std::vector<block> vec_m1;
		std::vector<block> vec_sendtoR(t);		
		uint8_t temp_level = level; 
		uint64_t temp_len = sub_len;
		
		
		// call FullEval t times
		for (auto i = 0; i < t; i++) {
			std::vector<block> vec_temp_leaf;
			if (i == t - 1){
				temp_level = level_last1;
				temp_len = last_len;
			}
			vec_sendtoR[i] = FullEval(temp_level, vec_k[i], vec_temp_leaf, vec_m0, vec_m1);
			vec_sendtoR[i] ^= vec_v[i];
			vec_temp_leaf.resize(temp_len);
			vec_leaf.insert(vec_leaf.end(), vec_temp_leaf.begin(), vec_temp_leaf.end());
		}
		
		// send t blocks to R 
		server_io.SendBlocks(vec_sendtoR.data(),t);
		
		// send vec_m0, vec_m1 to R by ALSZOTE 
		uint64_t EXTEND_LEN;
		if(selection_len % 128){
			uint64_t add_mod =128 - (selection_len % 128);
			EXTEND_LEN = selection_len + add_mod;
		}
		else{EXTEND_LEN = selection_len;}
    		std::string pp_filename = "alszote.pp"; 
    		ALSZOTE::PP pp; 
    		size_t BASE_LEN = 128;
    		if(!FileExist(pp_filename)){
        		pp = ALSZOTE::Setup(BASE_LEN); 
        		ALSZOTE::SavePP(pp, pp_filename); 
    		}
    		else{
        		ALSZOTE::FetchPP(pp, pp_filename);
    		}
    		ALSZOTE::Send(server_io, pp, vec_m0, vec_m1, EXTEND_LEN);

        	
		// set seed for ECCode
		PRG::Seed ec_seed;
		block ec_key = PRG::GenRandomBlocks(seed_k, 1)[0];
		ec_seed.aes_key = AES::GenEncKey(ec_key);
		server_io.SendBlock(ec_key);
		
		// encode vec_leaf by ExConvCode
		ExConvCode ECEncode;
		ECEncode.config(ec_seed);
		ECEncode.dualEncode(vec_leaf);	
		
		/*
		// print the output just for test
		N_item /= 2;		
		for(auto i = 0;i < N_item; ++i){
			std::cout << i << std::endl;
			Block::PrintBlock(vec_leaf[i]);
			std::cout << "  " << std::endl;
		}
		*/
	
	}
	
	//(2.2) return vec_A and vec_C with input vec_u and vec_w	
	std::vector<block> tmpVOLE_A(NetIO& client_io, uint64_t N_item, uint64_t t, std::vector<block>& vec_leaf, std::vector<block> vec_u, std::vector<block> vec_w) {
		if (!vec_leaf.empty()) {
			vec_leaf.clear();
		}
		N_item *= 2;// for EC Code mR=2
		
		// generate and save the t random punctured positions in vec_index 
		uint64_t sub_len = N_item / t;
		uint64_t last_len = N_item % t + N_item / t;
		std::vector<uint32_t> vec_index = GenRandomMod(sub_len, t - 1);
		uint32_t index_last1 = GenRandomMod(last_len, 1)[0];
		vec_index.push_back(index_last1);
		
		//  concatenate the t unit vector into base_field_A : base_field_A[vec_index[i]] = vec_u[i]
		block a0 = _mm_set_epi64x(0ll, 0ll);
		std::vector<block> base_field_A(N_item,a0);
		for (auto i = 0; i < t; ++i) {
			base_field_A[i * sub_len + vec_index[i]] = vec_u[i];
		}
		
		// obtain the right vec_select_bit (travel vec_indx reversely and XOR 111...111 )
		std::vector<uint8_t> vec_select_bit;
		uint8_t level = static_cast<uint8_t> (std::ceil(log2(sub_len)));
		uint8_t level_last1 = static_cast<uint8_t> (std::ceil(log2(last_len)));
		uint64_t leaf_num = 1ull << level;
		uint64_t leaf_num_last1 = 1ull << level_last1;
		uint64_t select_len = level * (t - 1) + level_last1;
		TransToBitVec(vec_index[t-1], vec_select_bit, level_last1);
		for (auto it = vec_index.rbegin()+1; it != vec_index.rend(); it++) {
			TransToBitVec(*it, vec_select_bit, level);
		}
		
		
		// receive vec_from_S from sender
		std::vector<block> vec_from_S(t);
		client_io.ReceiveBlocks(vec_from_S.data(),t);
		
		// receive vec_total_m by vec_select_bit
		std::vector<block> vec_total_m;
    		std::string pp_filename = "alszote.pp"; 
    		ALSZOTE::PP pp; 
    		size_t BASE_LEN = 128;
    		if(!FileExist(pp_filename)){
        		pp = ALSZOTE::Setup(BASE_LEN); 
        		ALSZOTE::SavePP(pp, pp_filename); 
    		}
    		else{
        		ALSZOTE::FetchPP(pp, pp_filename);
    		} 	
		uint64_t EXTEND_LEN;
		if(select_len % 128){
			uint64_t add_mod =128 - (select_len % 128);
			EXTEND_LEN = select_len + add_mod;
			
			vec_total_m = ALSZOTE::Receive(client_io, pp, vec_select_bit, EXTEND_LEN);
			vec_total_m.resize(select_len);
		}
		else{
			vec_total_m = ALSZOTE::Receive(client_io, pp, vec_select_bit, select_len);
		
		}	

             
		//call PuncEval t times to get vec_leaf 
		for (uint64_t i = 0; i < t; i++) {
			vec_from_S[i] ^= vec_w[i];
			//vec_from_S[i] = vec_w[i];
			std::vector<block> vec_temp_leaf;
			block* ptr_m = vec_total_m.data()+ (i*level);
			uint8_t* ptr_select_bit = vec_select_bit.data()+(i*level);
			//calculate the last pprf
			if (i == t - 1) {
				vec_temp_leaf = PuncEval(level_last1, vec_from_S[i], ptr_m, ptr_select_bit);
				vec_temp_leaf.resize(last_len);
				vec_leaf.insert(vec_leaf.end(), vec_temp_leaf.begin(), vec_temp_leaf.end());
				break;
			}

			// calculate the first r-1 pprf
			vec_temp_leaf = PuncEval(level, vec_from_S[i], ptr_m, ptr_select_bit);
			vec_temp_leaf.resize(sub_len);
			vec_leaf.insert(vec_leaf.end(), vec_temp_leaf.begin(), vec_temp_leaf.end());
		}
		
		

		// set seed for ECCode
		block ec_key;
		client_io.ReceiveBlock(ec_key);
		PRG::Seed ec_seed;
		ec_seed.aes_key = AES::GenEncKey(ec_key);
		
		// encode vec_A and vec_C by ExConvCode		
		ExConvCode ECEncode;
		ECEncode.config(ec_seed);
		ECEncode.dualEncode2(vec_leaf, base_field_A);

		/*
		// print the output just for test
		N_item /= 2;
		block delta = _mm_set_epi64x(0x2c9e2e7639500ed4,0x97f40bbf3a16f778);
		for(auto i = 0; i < N_item; ++i){
			std::cout << i << std::endl;
			if(!Block::Compare(a0,base_field_A[i])){
				 //std::cout << i << std::endl;
				Block::PrintBlock(vec_leaf[i]^gf128_mul(base_field_A[i],delta));
				PrintSplitLine('-');
			}
			else{Block::PrintBlock(vec_leaf[i]);}
			//Block::PrintBlock(vec_leaf[i]);
			
			std::cout << "  " << std::endl;
		}
		*/
		
		return base_field_A;
	}



	//(3) spVOLE = FullEval + PuncEval
	//(3.1)
	block FullEval(uint8_t depth, block k, std::vector<block>& vec_leaf, std::vector<block>& vec_m0, std::vector<block>& vec_m1){
		
		if(!vec_leaf.empty()){
			vec_leaf.clear();
		}
		uint64_t leaf_num = static_cast<uint64_t>(1ull) << depth;
		uint64_t half_leaf_num = static_cast<uint64_t>(1ull) << (depth - 1);
		uint64_t inner_num = leaf_num - 2;
		std::vector<block> vec_inner(inner_num);
		
		//generate vec_inner
		std::vector<block> vec_temp; 
		vec_temp = GGM_PRG(k);
		vec_inner[0] = vec_temp[0];
		vec_inner[1] = vec_temp[1];
		auto parent_i = 0;
		for(auto child_j = 2; child_j < inner_num; child_j+=2){
			vec_temp = GGM_PRG(vec_inner[parent_i]);
			vec_inner[2*parent_i + 2] = vec_temp[0];
			vec_inner[2*parent_i + 3] = vec_temp[1];
			parent_i += 1;
		}
		
		// generate vec_leaf with vec_inner[]
		for (; parent_i < inner_num; ++parent_i){
			vec_temp = GGM_PRG(vec_inner[parent_i]);
			vec_leaf.push_back(vec_temp[0]);
			vec_leaf.push_back(vec_temp[1]);
		}
		
		// generate vec_m0, vec_m1
		vec_m0.push_back(vec_inner[0]);
		vec_m1.push_back(vec_inner[1]);
		block temp_m0;
		block temp_m1;
		uint64_t left_index = 2;
		for (auto i = 1; i < depth - 1; ++i){
			uint64_t level_node_num = 1ull << i;
			temp_m0 = Block::zero_block;
			temp_m1 = Block::zero_block;
			for (auto j = 0; j < level_node_num; ++j,left_index += 2){
				temp_m0 ^= vec_inner[left_index];
				temp_m1 ^= vec_inner[left_index+1];
			} 
			vec_m0.push_back(temp_m0);
			vec_m1.push_back(temp_m1); 
		}
		temp_m0 = vec_leaf[0];
		temp_m1 = vec_leaf[1];
		for (auto i = 2; i < leaf_num; i += 2){
			temp_m0 ^= vec_leaf[i];
			temp_m1 ^= vec_leaf[i+1];
		}
		vec_m0.push_back(temp_m0);
		vec_m1.push_back(temp_m1);
		
		return (temp_m0 ^ temp_m1);
	}
	
	
	struct Punc_Node {
		block node;
		bool flag = 0; //1 if node is filled; else 0
	};	
	
	//(3.2)
	std::vector<block> PuncEval(uint8_t depth, block beta, block* ptr_m, uint8_t* ptr_selection_bit){
		uint64_t leaf_num = static_cast<uint64_t>(1ull) << depth;
		uint64_t half_leaf_num = static_cast<uint64_t>(1ull) << (depth - 1);
		Punc_Node* ptr_inner = new Punc_Node[leaf_num - 2];
		std::vector<block> vec_leaf(leaf_num);
		
		// generate the first level of inner nodes
		if (*ptr_selection_bit == 0){
			ptr_inner[0].node = *ptr_m;
			ptr_inner[0].flag = 1;
		}
		else {
			ptr_inner[1].node = *ptr_m;
			ptr_inner[1].flag = 1;
		}		
		++ptr_m;
		++ptr_selection_bit;

		//to indicate the parent node 
		uint64_t parent_i = 0;
		// to mark the index of unfilled parent node
		uint64_t alpha_i;	
		
		// generate the remaining inner_node by parent_i and alpha_i
		std::vector<block> vec_temp; 
		block left_sum;
		block right_sum;
		for (auto i = 1; i < depth - 1; ++i){
			left_sum = Block::zero_block;//set as 0 block
			right_sum = Block::zero_block;//set as 0 block
			uint64_t level_node_num = static_cast<uint64_t>(1ull) << i;
			
			for (auto j = 0; j < level_node_num; ++j, ++parent_i){
				if (ptr_inner[parent_i].flag == 1){
					vec_temp = GGM_PRG(ptr_inner[parent_i].node);
					
					// generate the left child of inner_node[parent_i]
					ptr_inner[(2 * parent_i) + 2].node = vec_temp[0];
					ptr_inner[(2 * parent_i) + 2].flag = 1;
					// generate the right child of inner_node[parent_i]
					ptr_inner[(2 * parent_i) + 3].node = vec_temp[1];
					ptr_inner[(2 * parent_i) + 3].flag = 1;
					
					// calculate the sum of left_node/right_node 
					left_sum ^= vec_temp[0];
					right_sum ^= vec_temp[1];
				
				}
				else{
					alpha_i = parent_i;
				}
			}
			// generate the brother node of chosen node
			if (*ptr_selection_bit == 0){
				ptr_inner[(2 * alpha_i) + 2].node = (*ptr_m) ^ left_sum;
				ptr_inner[(2 * alpha_i) + 2].flag = 1;
			}
			else{
				ptr_inner[(2 * alpha_i) + 3].node = (*ptr_m) ^ right_sum;
				ptr_inner[(2 * alpha_i) + 3].flag = 1;
			}
			++ptr_m;
			++ptr_selection_bit;
		}
		
		//calculate vec_leaf besides punctured node
		left_sum = Block::zero_block;
		right_sum = Block::zero_block;
		for (auto i = 0; i < half_leaf_num; ++i, ++parent_i){
			if (ptr_inner[parent_i].flag == 1) {
				vec_temp = GGM_PRG(ptr_inner[parent_i].node);
				vec_leaf[2*i] = vec_temp[0];
				vec_leaf[2*i+1] = vec_temp[1];
				
				left_sum ^= vec_temp[0];
				right_sum ^= vec_temp[1];
			}
			else{
				alpha_i = i;
			}
		}
		
		//correct the leaf of punctured node
		if(*ptr_selection_bit == 0){
			vec_leaf[2 * alpha_i] = (*ptr_m) ^ left_sum;
			vec_leaf[2 * alpha_i+1] = (*ptr_m) ^ right_sum ^ beta;
		}
		else{
			vec_leaf[2 * alpha_i] = (*ptr_m) ^ left_sum ^ beta;
			vec_leaf[2 * alpha_i+1] = (*ptr_m) ^ right_sum;
		}
		
		delete[] ptr_inner;
		return vec_leaf;
	}	
	
	// use as 1_to_2 PRG
	inline std::vector<block> GGM_PRG(block in)
	{
		PRG::Seed seed;
		seed.aes_key = AES::GenEncKey(in);	
		std::vector<block> vec_a(2);
		vec_a[0] =_mm_set_epi64x(0ll, 1ll);
		vec_a[1] =_mm_set_epi64x(0ll, 2ll);
		AES::FastECBEnc(seed.aes_key, vec_a.data(), 2);	
		return vec_a;
	}	
	
	//For instance: vec_bit = {...}, TransToBitVec(13,vec_bit,6); vec_bit={1,1,0,0,1,0...}
	inline void TransToBitVec(uint64_t num, std::vector<uint8_t>& vec_bit, uint8_t LEN) {
		for (auto i = 0; i < LEN; i++) {
			if (num % 2 == 1) {
				vec_bit.insert(vec_bit.begin(), 0);
			}
			else {
				vec_bit.insert(vec_bit.begin(), 1);
			}
			num >>= 1;
		}
	}	
	
	
}
#endif
