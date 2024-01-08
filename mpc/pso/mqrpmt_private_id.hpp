#ifndef KUNLUN_MQRPMT_PrivateID_HPP_
#define KUNLUN_MQRPMT_PrivateID_HPP_

#include "../pso/mqrpmt_psu.hpp"
#include "../oprf/ote_oprf.hpp"
#include "../oprf/vole_oprf.hpp"

/*
** implement Private-ID based on distributed OPRF and PSU
*/

//#define OPRF OTEOPRF
#define OPRF VOLEOPRF

namespace mqRPMTPrivateID{

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    OPRF::PP oprf_part; 
    mqRPMTPSU::PP psu_part; 

    size_t LOG_SENDER_ITEM_NUM; 
    size_t LOG_RECEIVER_ITEM_NUM; 
    size_t SENDER_ITEM_NUM; 
    size_t RECEIVER_ITEM_NUM; 
};


PP Setup(size_t LOG_PRF_INPUT_LEN, 
        size_t computational_security_parameter, 
        size_t statistical_security_parameter, 
        size_t LOG_SENDER_ITEM_NUM, size_t LOG_RECEIVER_ITEM_NUM)
{
    PP pp; 

    pp.oprf_part = OPRF::Setup(LOG_PRF_INPUT_LEN, statistical_security_parameter); 
    pp.psu_part = mqRPMTPSU::Setup(computational_security_parameter, statistical_security_parameter, 
                                   LOG_SENDER_ITEM_NUM, LOG_RECEIVER_ITEM_NUM); 

    pp.LOG_SENDER_ITEM_NUM = LOG_SENDER_ITEM_NUM; 
    pp.LOG_RECEIVER_ITEM_NUM = LOG_RECEIVER_ITEM_NUM; 
    pp.SENDER_ITEM_NUM = size_t(pow(2, pp.LOG_SENDER_ITEM_NUM));
    pp.RECEIVER_ITEM_NUM = size_t(pow(2, pp.LOG_RECEIVER_ITEM_NUM)); 

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

    fout << pp.oprf_part; 
    fout << pp.psu_part; 

    fout << pp.LOG_SENDER_ITEM_NUM; 
    fout << pp.LOG_RECEIVER_ITEM_NUM; 
    fout << pp.SENDER_ITEM_NUM; 
    fout << pp.RECEIVER_ITEM_NUM; 

    fout.close(); 
}

// load pp from file
void FetchPP(PP &pp, std::string pp_filename)
{
    std::ifstream fin; 
    fin.open(pp_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }

    fin >> pp.oprf_part; 
    fin >> pp.psu_part;

    fin >> pp.LOG_SENDER_ITEM_NUM; 
    fin >> pp.LOG_RECEIVER_ITEM_NUM; 
    fin >> pp.SENDER_ITEM_NUM; 
    fin >> pp.RECEIVER_ITEM_NUM; 

    fin.close(); 
}

// returns union_id and X_id
std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
Send(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t ITEM_LEN)
{
    if(vec_X.size() != pp.SENDER_ITEM_NUM){
        std::cerr << "|X| does not match public parameter" << std::endl; 
        exit(1); // EXIT_FAILURE  
    }

    auto start_time = std::chrono::steady_clock::now();   
    PrintSplitLine('-');

    std::cout << "[Private-ID from distributed OPRF+PSU] Phase 1: compute sender's ID using distributed OPRF (run OPRF twice)>>>" << std::endl;

    // first act as server: compute F_k1(X)
    std::vector<uint8_t> k1 = OPRF::Server(io, pp.oprf_part); 
    std::vector<std::vector<uint8_t>> vec_Fk1_X = OPRF::Evaluate(pp.oprf_part, k1, vec_X, pp.SENDER_ITEM_NUM); 
    // then act as client: compute F_k2(X)
    std::vector<std::vector<uint8_t>> vec_Fk2_X = OPRF::Client(io, pp.oprf_part, vec_X, pp.SENDER_ITEM_NUM); 
    // compute F_k(X) = F_k1(X) xor F_k2(X)
    std::vector<std::vector<uint8_t>> vec_X_id(pp.SENDER_ITEM_NUM);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SENDER_ITEM_NUM; i++){
        vec_X_id[i] = XOR(vec_Fk1_X[i], vec_Fk2_X[i]); 
    }     

    std::cout << "[Private-ID from distributed OPRF+PSU] Phase 2: execute PSU >>>" << std::endl;
    mqRPMTPSU::Send(io, pp.psu_part, vec_X_id, ITEM_LEN);

    std::vector<std::vector<uint8_t>> vec_union_id; 
    io.ReceiveBytesVector(vec_union_id); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[Private-ID from distributed OPRF+PSU]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return {vec_union_id, vec_X_id};
}

// returns union_id and X_id
std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t ITEM_LEN) 
{
    if(vec_Y.size() != pp.RECEIVER_ITEM_NUM){
        std::cerr << "|Y| does not match public parameter" << std::endl; 
        exit(1); // EXIT_FAILURE  
    }
    
    auto start_time = std::chrono::steady_clock::now();  
    PrintSplitLine('-');

    std::cout << "[Private-ID from distributed OPRF+PSU] Phase 1: compute receiver's ID using distributed OPRF (run OPRF twice)>>>" << std::endl;

    // first act as client: compute F_k1(Y)
    std::vector<std::vector<uint8_t>> vec_Fk1_Y = OPRF::Client(io, pp.oprf_part, vec_Y, pp.RECEIVER_ITEM_NUM); 

    // then act as server: compute F_k2(Y)
    std::vector<uint8_t> k2 = OPRF::Server(io, pp.oprf_part);     
    std::vector<std::vector<uint8_t>> vec_Fk2_Y = OPRF::Evaluate(pp.oprf_part, k2, vec_Y, pp.RECEIVER_ITEM_NUM);  

    // compute F_k(Y) = F_k1(Y) xor F_k2(Y)
    std::vector<std::vector<uint8_t>> vec_Y_id(pp.RECEIVER_ITEM_NUM);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.RECEIVER_ITEM_NUM; i++){
        vec_Y_id[i] = XOR(vec_Fk1_Y[i], vec_Fk2_Y[i]); 
    }     

    PrintSplitLine('-');
    std::cout << "[Private-ID from distributed OPRF+PSU] Phase 2: execute PSU >>>" << std::endl;

    std::vector<std::vector<uint8_t>> vec_union_id = mqRPMTPSU::Receive(io, pp.psu_part, vec_Y_id, ITEM_LEN); 

    size_t UNION_SIZE = vec_union_id.size(); 
    
    PrintSplitLine('-');
    std::cout << "[Private-ID from distributed OPRF+PSU] Phase 3: Receiver ===> vec_union_id >>> Sender";
    std::cout << " [" << (double)ITEM_LEN*UNION_SIZE/(1024*1024) << " MB]" << std::endl;

    io.SendBytesVector(vec_union_id); 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[Private-ID from distributed OPRF+PSU]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
       
    return {vec_union_id, vec_Y_id};
}
 
}
#endif
