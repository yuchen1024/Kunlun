/*
** Modified from the following project
** 1. https://github.com/emp-ot/
*/

#ifndef KUNLUN_NP_OT_HPP__
#define KUNLUN_NP_OT_HPP__

#include "../../include/kunlun.hpp"


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

void PrintPP(const PP &pp)
{
	pp.g.Print("g"); 
}

// serialize pp to stream
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
	fout << pp.g; 
	return fout; 
}

// deserialize pp from stream
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
	fin >> pp.g; 
	return fin; 
}

PP Setup()
{
	PP pp; 
	pp.g = ECPoint(generator);
	return pp; 
}

// save pp to file
void SavePP(PP &pp, std::string pp_filename)
{
	std::ofstream fout; 
    fout.open(pp_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << pp; 
    fout.close(); 
}


// fetch pp from file
void FetchPP(PP &pp, std::string pp_filename)
{
	std::ifstream fin; 
    fin.open(pp_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
	fin >> pp; 
    fin.close(); 
}

void Send(NetIO &io, PP &pp, const std::vector<block>& vec_m0, const std::vector<block> &vec_m1, size_t LEN)
{	
	PrintSplitLine('-');
	auto start_time = std::chrono::steady_clock::now(); 

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
	#pragma omp parallel for num_threads(thread_count)
	for(auto i = 0; i < LEN; i++) {
		vec_r[i] = GenRandomBigIntLessThan(order);
		vec_X[i] = pp.g * vec_r[i];
		vec_Z[i] = C * vec_r[i];
	}

	// send C
	io.SendECPoints(&C, 1);
	io.SendECPoints(vec_X.data(), LEN); 

	std::cout <<"Naor-Pinkas OT [step 1]: Sender ===> (C, vec_X) ===> Receiver";
    std::cout << " [" << (double)POINT_BYTE_LEN*(LEN+1)/(1024*1024) << " MB]" << std::endl;

	io.ReceiveECPoints(vec_pk0.data(), LEN); 

	std::vector<ECPoint> vec_K0(LEN); // session key
	std::vector<ECPoint> vec_K1(LEN); // session key
	std::vector<block> vec_Y0(LEN);  
	std::vector<block> vec_Y1(LEN); 

	// send m0 and m1
	#pragma omp parallel for num_threads(thread_count)
	for(auto i = 0 ; i < LEN; ++i) {
		vec_K0[i] = vec_pk0[i] * vec_r[i];
		vec_K1[i] = vec_Z[i] - vec_K0[i];
		vec_Y0[i] = Hash::ECPointToBlock(vec_K0[i]) ^ vec_m0[i];
		vec_Y1[i] = Hash::ECPointToBlock(vec_K1[i]) ^ vec_m1[i];
	}

	io.SendBlocks(vec_Y0.data(), LEN);
	io.SendBlocks(vec_Y1.data(), LEN);

	std::cout <<"Naor-Pinkas OT [step 3]: Sender ===> (vec_Y0, vec_Y1) ===> Receiver";
    std::cout << " [" << (double)POINT_BYTE_LEN*LEN*2/(1024*1024) << " MB]" << std::endl;

	auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "Naor-Pinkas OT: Sender side takes time " 
	          << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

	PrintSplitLine('-');
}

std::vector<block> Receive(NetIO &io, PP &pp, const std::vector<uint8_t> &vec_selection_bit, size_t LEN)
{	
	PrintSplitLine('-');
	auto start_time = std::chrono::steady_clock::now(); 
	std::vector<block> vec_result(LEN);  
	if(vec_result.size()!=LEN || vec_selection_bit.size()!=LEN){
		std::cerr << "size does not match" << std::endl; 
	}

	std::vector<BigInt> vec_sk(LEN);
	std::vector<ECPoint> vec_X(LEN); 
	std::vector<ECPoint> vec_pk0(LEN);
	
	ECPoint C; 	
	io.ReceiveECPoints(&C, 1); 
	io.ReceiveECPoints(vec_X.data(), LEN);

	// send pk0[i]
	#pragma omp parallel for num_threads(thread_count)
	for(auto i = 0; i < LEN; i++) {
		vec_sk[i] = GenRandomBigIntLessThan(order);
		vec_pk0[i] = pp.g * vec_sk[i];
		if(vec_selection_bit[i] == 1){
			vec_pk0[i] = C - vec_pk0[i]; 
		}
	}

	io.SendECPoints(vec_pk0.data(), LEN);

	std::cout <<"Naor-Pinkas OT [step 2]: Receiver ===> vec_pk0 ===> Sender";
    std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;

	// compute Kb[i]
	std::vector<ECPoint> vec_K(LEN); 
	std::vector<block> vec_Y0(LEN); 
	std::vector<block> vec_Y1(LEN); 

	io.ReceiveBlocks(vec_Y0.data(), LEN);
	io.ReceiveBlocks(vec_Y1.data(), LEN); 

	// decrypt with Kb[i]
	#pragma omp parallel for num_threads(thread_count)
	for(auto i = 0; i < LEN; i++) {
		vec_K[i] = vec_X[i] * vec_sk[i];
		if(vec_selection_bit[i] == 0){
			vec_result[i] = vec_Y0[i] ^ Hash::ECPointToBlock(vec_K[i]);
		}
		else{
			vec_result[i] = vec_Y1[i] ^ Hash::ECPointToBlock(vec_K[i]);
		}
	}

	std::cout <<"Naor-Pinkas OT [step 4]: Receiver obtains vec_m" << std::endl;

	auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "Naor-Pinkas OT: Receiver side takes time " 
	          << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-');
	return vec_result; 
}

}

#endif
