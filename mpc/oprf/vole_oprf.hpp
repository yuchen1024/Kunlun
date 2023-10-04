/* vole_oprf = VOLE + OKVS  */

#include "../okvs/Baxos.hpp"
#include"../vole/vole.h"
#include <omp.h>
#include <iostream>
#include <vector>
#include "../../netio/stream_channel.hpp"
#include "../../utility/print.hpp"
#include "../../crypto/block.hpp"
inline std::vector<std::vector<uint8_t>> Block_TO_U8(std::vector<block> Vec){
        auto size=Vec.size();
        std::vector<std::vector<uint8_t>> ans(size,std::vector<uint8_t>(16));
        for(auto i=0;i<size;i++){
            memcpy(ans[i].data(),&Vec[i],16);
        }
        return ans;
    }

inline std::vector<block> U8_TO_Block(std::vector<std::vector<uint8_t>> matrixx){
	auto size = matrixx.size();
	std::vector<block> ans(size);
	for(auto i=0;i<size;i++){
		memcpy(ans.data()+i,matrixx[i].data(),16);
	}
	return ans;
}


namespace VOLEOPRF
{
    struct PP
    {
        size_t LEN; // the length of the client's input vector

        size_t okvs_bin_size;    // the bin size in multi-threaded OKVS
        Baxos<gf_128> okvs;      // OKVS object
        size_t okvs_output_size; // the size of the output vector obtained in the OKVS encoding process

        // a common PRG seed, used to generate some random blocks
        PRG::Seed common_seed;

        // the data that needs to be saved during the interaction for the Evaluate evaluation
        block Delta;
        block W;

        size_t thread_num;
        size_t OUTPUT_LEN; // byte length of each item
    };

    PP Setup(size_t LOG_LEN, size_t statistical_security_parameter = 40)
    {
        PP pp;
        pp.LEN = 1ull << LOG_LEN; // LEN = 2^{LOG_LEN}
        pp.okvs_bin_size = 1ull << 15;
        pp.okvs = Baxos<gf_128>(pp.LEN, pp.okvs_bin_size, 3, statistical_security_parameter);
        pp.okvs_output_size = pp.okvs.bin_num * pp.okvs.total_size;
        pp.common_seed = PRG::SetSeed(fixed_seed, 0);
        //pp.thread_num = omp_get_max_threads();
        pp.thread_num = 1;
        pp.OUTPUT_LEN = 16; // byte length of each item
        return pp;
    }
    std::vector<std::vector<uint8_t>> Client(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t ITEM_NUM)
    {
        auto start_time = std::chrono::steady_clock::now();
        // the seed used to generate the initial random data
        PRG::Seed seed = PRG::SetSeed();

        // Fig 4.Step 2:Sample r
        block seed_r = PRG::GenRandomBlocks(seed, 1)[0];
        PRG::Seed okvs_seed = PRG::SetSeed(&seed_r, 0);
        pp.okvs.seed = okvs_seed;

        // Fig 4.Step 2:the receiver solves the systems
        auto size = pp.okvs_output_size;
        block a0 = _mm_set_epi64x(0ll, 0ll);
        std::vector<block> vec_zero(ITEM_NUM,a0);
        
        std::vector<block> P(size);
        pp.okvs.solve(vec_Y, vec_zero, P, nullptr, pp.thread_num);

        // Fig 4.Step 3:VOLE
        std::vector<block> A;
        std::vector<block> C;
        PrintSplitLine('-');
        //std::cout << "length of VOLE = " << size << std::endl; 
        A = VOLE::VOLE_A(io, size, C); 


        // Fig 4.Step 4:send r
        io.SendBlock(seed_r);

        uint64_t i = 0;
        for (; i + 8 <= size; i += 8)
        {
            P[i] ^= A[i];
            P[i + 1] ^= A[i + 1];
            P[i + 2] ^= A[i + 2];
            P[i + 3] ^= A[i + 3];
            P[i + 4] ^= A[i + 4];
            P[i + 5] ^= A[i + 5];
            P[i + 6] ^= A[i + 6];
            P[i + 7] ^= A[i + 7];
        }
        for (; i < size; i++)
        {
            P[i] ^= A[i];
        }

        // Fig 4.Step 4:send A=P+A'
        io.SendBlocks(P.data(), P.size());


        // Prepare for Fig 4.Step 6 Decode(C,x)
        std::vector<block> output(ITEM_NUM);
        pp.okvs.decode(vec_Y, output, C, pp.thread_num);
        auto end_time = std::chrono::steady_clock::now();
        
    	PrintSplitLine('-');
    std::cout << "VOLE-based OPRF[Step 1]: Receiver ===> vec_A ===> Sender [" 
              << (double)(P.size())/(1 << 16) << " MB]" << std::endl; 
                     
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF[Step 2]: Receiver side takes time "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms to calculate vec_A and vec_Fk_Y." << std::endl;
        PrintSplitLine('-');
        return Block_TO_U8(output);
    }

    std::vector<std::vector<uint8_t>> Server(NetIO &io, PP &pp)
    //std::vector<block> Server(NetIO &io, PP &pp)
    {
        PrintSplitLine('-');
	
	auto start_time = std::chrono::steady_clock::now();
        // the seed used to generate the initial random data
        PRG::Seed seed = PRG::SetSeed();
        auto random_blocks = PRG::GenRandomBlocks(seed, 2);

        // Fig.4 Step 1:the Sender samples ws 鈫?F
        pp.Delta = random_blocks[1];
        auto size = pp.okvs_output_size;

        // Fig 4.Step 3:VOLE 
        std::vector<block> K;
        VOLE::VOLE_B(io, size, K,pp.Delta);

	        
        // Fig 4.Step 4: the sender receives r
        block seed_r;
        io.ReceiveBlock(seed_r);

        PRG::Seed okvs_seed = PRG::SetSeed(&seed_r, 0);
        pp.okvs.seed = okvs_seed;

        block *K_pointer = K.data();
 
        // Fig 4.Step 4: the sender receives A
        auto A = std::vector<block>(size);
        auto P_pointer = A.data();
        io.ReceiveBlocks(P_pointer, size);

        // Fig 4.Step 4: the sender computes K=B+A*Delta
        uint64_t i = 0;
        auto Delta = pp.Delta;
        for (; i + 8 <= size; i += 8, K_pointer += 8, P_pointer += 8)
        {
            K_pointer[0] ^= gf128_mul(Delta, P_pointer[0]);
            K_pointer[1] ^= gf128_mul(Delta, P_pointer[1]);
            K_pointer[2] ^= gf128_mul(Delta, P_pointer[2]);
            K_pointer[3] ^= gf128_mul(Delta, P_pointer[3]);
            K_pointer[4] ^= gf128_mul(Delta, P_pointer[4]);
            K_pointer[5] ^= gf128_mul(Delta, P_pointer[5]);
            K_pointer[6] ^= gf128_mul(Delta, P_pointer[6]);
            K_pointer[7] ^= gf128_mul(Delta, P_pointer[7]);
        }
        for (; i < size; i++, K_pointer++, P_pointer++)
        {
            *K_pointer ^= gf128_mul(Delta, *P_pointer);
        }

        auto end_time = std::chrono::steady_clock::now();
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF[Step 3]: Sender side takes: "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms to calculate OPRF_KEY." << std::endl;
        return Block_TO_U8(K);
        
    }

    std::vector<std::vector<uint8_t>> Evaluate(PP &pp, std::vector<std::vector<uint8_t>> &u8_oprf_key, std::vector<block> &vec_X, size_t ITEM_NUM)
    
    {
        
        //transform u8 to block
        std::vector<block> oprf_key = U8_TO_Block(u8_oprf_key);
        
        std::vector<block> output(ITEM_NUM);
        auto start_time = std::chrono::steady_clock::now();
        pp.okvs.decode(vec_X, output, oprf_key, 1);

        // transform block to u8
        //u8_oprf_key = Block_TO_U8(oprf_key);
        
        auto end_time = std::chrono::steady_clock::now();
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF[Step 4]: Sender side takes: "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms to calculate vec_Fk_X." << std::endl;
        PrintSplitLine('-');
        return Block_TO_U8(output);
    }
    
    //Client1, Server1 and Evaluate1 just for test_voleoprf.cpp

    std::vector<block> Client1(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t ITEM_NUM)
    {
        
        // the seed used to generate the initial random data
        PRG::Seed seed = PRG::SetSeed();

        // Fig 4.Step 2:Sample r
        block seed_r = PRG::GenRandomBlocks(seed, 1)[0];
        PRG::Seed okvs_seed = PRG::SetSeed(&seed_r, 0);
        pp.okvs.seed = okvs_seed;

        // Fig 4.Step 2:the receiver solves the systems
        auto size = pp.okvs_output_size;
        block a0 = _mm_set_epi64x(0ll, 0ll);
        std::vector<block> vec_zero(ITEM_NUM,a0);
        
        std::vector<block> P(size);
        pp.okvs.solve(vec_Y, vec_zero, P, nullptr, pp.thread_num);

        // Fig 4.Step 3:VOLE
        std::vector<block> A;
        std::vector<block> C;
        PrintSplitLine('-');
        //std::cout << "length of VOLE = " << size << std::endl; 
        A = VOLE::VOLE_A(io, size, C); 


        // Fig 4.Step 4:send r
        io.SendBlock(seed_r);

        uint64_t i = 0;
        for (; i + 8 <= size; i += 8)
        {
            P[i] ^= A[i];
            P[i + 1] ^= A[i + 1];
            P[i + 2] ^= A[i + 2];
            P[i + 3] ^= A[i + 3];
            P[i + 4] ^= A[i + 4];
            P[i + 5] ^= A[i + 5];
            P[i + 6] ^= A[i + 6];
            P[i + 7] ^= A[i + 7];
        }
        for (; i < size; i++)
        {
            P[i] ^= A[i];
        }

        // Fig 4.Step 4:send A=P+A'
        io.SendBlocks(P.data(), P.size());


        // Prepare for Fig 4.Step 6 Decode(C,x)
        std::vector<block> output(ITEM_NUM);
        pp.okvs.decode(vec_Y, output, C, pp.thread_num);
        
    	PrintSplitLine('-');
    std::cout << "VOLE-based OPRF: Receiver ===> vector_A ===> Sender [" 
              << (double)(P.size())/(1 << 16) << " MB]" << std::endl; 
                     
        return output;
    }

    std::vector<block> Server1(NetIO &io, PP &pp)
    {
        PrintSplitLine('-');

        // the seed used to generate the initial random data
        PRG::Seed seed = PRG::SetSeed();
        auto random_blocks = PRG::GenRandomBlocks(seed, 2);

        // Fig.4 Step 1:the Sender samples ws 鈫?F
        pp.Delta = random_blocks[1];
        auto size = pp.okvs_output_size;

        // Fig 4.Step 3:VOLE
        //PrintSplitLine('-');
        //std::cout << "length of VOLE = " << size << std::endl; 
        std::vector<block> K;
        VOLE::VOLE_B(io, size, K,pp.Delta);

	        
        // Fig 4.Step 4: the sender receives r
        block seed_r;
        io.ReceiveBlock(seed_r);

        PRG::Seed okvs_seed = PRG::SetSeed(&seed_r, 0);
        pp.okvs.seed = okvs_seed;

        block *K_pointer = K.data();
 
        // Fig 4.Step 4: the sender receives A
        auto A = std::vector<block>(size);
        auto P_pointer = A.data();
        io.ReceiveBlocks(P_pointer, size);

        // Fig 4.Step 4: the sender computes K=B+A*Delta
        uint64_t i = 0;
        auto Delta = pp.Delta;
        for (; i + 8 <= size; i += 8, K_pointer += 8, P_pointer += 8)
        {
            K_pointer[0] ^= gf128_mul(Delta, P_pointer[0]);
            K_pointer[1] ^= gf128_mul(Delta, P_pointer[1]);
            K_pointer[2] ^= gf128_mul(Delta, P_pointer[2]);
            K_pointer[3] ^= gf128_mul(Delta, P_pointer[3]);
            K_pointer[4] ^= gf128_mul(Delta, P_pointer[4]);
            K_pointer[5] ^= gf128_mul(Delta, P_pointer[5]);
            K_pointer[6] ^= gf128_mul(Delta, P_pointer[6]);
            K_pointer[7] ^= gf128_mul(Delta, P_pointer[7]);
        }
        for (; i < size; i++, K_pointer++, P_pointer++)
        {
            *K_pointer ^= gf128_mul(Delta, *P_pointer);
        }
        
        return K;
    }

    
    std::vector<block> Evaluate1(PP &pp, std::vector<block> &oprf_key, std::vector<block> &vec_X, size_t ITEM_NUM)
    {
  
        std::vector<block> output(ITEM_NUM);
        pp.okvs.decode(vec_X, output, oprf_key, 1);

        return output;
    }
    
}
