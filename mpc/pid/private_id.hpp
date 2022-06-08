#ifndef KUNLUN_PID_HPP_
#define KUNLUN_PID_HPP_

#include "../pso/pso_from_mqrpmt.hpp"
#include "../oprf/oprf_from_ote.hpp"
#include "../pid/private_id.hpp"


/*
** implement Private-ID based on OPRF and PSU
*/

namespace PID{

struct PP
{
    OTEOPRF::PP oprf_part; 
    PSO::PP pso_part; 
};

PP Setup(size_t LOG_LEN, std::string filter_type, size_t statistical_security_parameter)
{
    PP pp; 
    pp.oprf_part = OTEOPRF::Setup(LOG_LEN, statistical_security_parameter); 
    pp.pso_part = PSO::Setup(filter_type, statistical_security_parameter); 
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
    fout << pp.pso_part; 

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
    fin >> pp.pso_part;

    fin.close(); 
}

// returns union_id and X_id
std::tuple<std::vector<std::string>, std::vector<std::string>> Send(NetIO &io, 
          PP &pp, std::vector<block> &vec_X, size_t ITEM_LEN, size_t ITEM_NUM)
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');

    std::cout << "Phase 1: compute sender's ID using OPRF >>>" << std::endl;

    // first act as server: compute F_k1(X)
    std::vector<std::vector<uint8_t>> k1; 
    k1 = OTEOPRF::Server(io, pp.oprf_part); 
    std::vector<std::string> vec_Fk1_X = OTEOPRF::Evaluate(pp.oprf_part, k1, vec_X, ITEM_NUM); 
    // then act as client: compute F_k2(X)
    std::vector<std::string> vec_Fk2_X = OTEOPRF::Client(io, pp.oprf_part, vec_X, ITEM_NUM); 
    // compute F_k(X) = F_k1(X) xor F_k2(X)
    std::vector<std::string> vec_X_id(ITEM_NUM);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ITEM_NUM; i++){
        vec_X_id[i] = XOR(vec_Fk1_X[i], vec_Fk2_X[i]); 
    }     

    std::cout << "Phase 2: execute PSU >>>" << std::endl;
    PSO::PSU::Send(io, pp.pso_part, vec_X_id, ITEM_LEN, ITEM_NUM);

    size_t UNION_SIZE; 
    io.ReceiveInteger(UNION_SIZE); 
    std::cout << "UNION_SIZE = " << UNION_SIZE << std::endl; 

    std::vector<std::string> vec_union_id(UNION_SIZE, std::string(ITEM_LEN, '0'));  
    
    io.ReceiveBytes(vec_union_id.data(), ITEM_LEN*UNION_SIZE); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[Private-ID from PPRF+PSU]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return {vec_union_id, vec_X_id};
}

// returns union_id and X_id
std::tuple<std::vector<std::string>, std::vector<std::string>> Receive(NetIO &io, 
                    PP &pp, std::vector<block> &vec_Y, size_t ITEM_LEN, size_t ITEM_NUM) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');

    std::cout << "Phase 1: compute receiver's ID using OPRF >>>" << std::endl;

    // first act as client: compute F_k1(Y)
    std::vector<std::string> vec_Fk1_Y = OTEOPRF::Client(io, pp.oprf_part, vec_Y, ITEM_NUM); 

    std::cout << "here" << std::endl;

    // then act as server: compute F_k2(Y)
    std::vector<std::vector<uint8_t>> k2; 
    k2 = OTEOPRF::Server(io, pp.oprf_part); 
    std::vector<std::string> vec_Fk2_Y = OTEOPRF::Evaluate(pp.oprf_part, k2, vec_Y, ITEM_NUM);  
    // compute F_k(Y) = F_k1(Y) xor F_k2(Y)
    std::vector<std::string> vec_Y_id(ITEM_NUM);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ITEM_NUM; i++){
        vec_Y_id[i] = XOR(vec_Fk1_Y[i], vec_Fk2_Y[i]); 
    }     

    std::cout << "Phase 2: execute PSU >>>" << std::endl;

    std::vector<std::string> vec_union_id; 
    
    vec_union_id = PSO::PSU::Receive(io, pp.pso_part, vec_Y_id, ITEM_LEN, ITEM_NUM); 

    size_t UNION_SIZE = vec_union_id.size(); 
    std::cout << "UNION_SIZE = " << UNION_SIZE << std::endl; 

    io.SendInteger(UNION_SIZE); 

    io.SendBytes(vec_union_id.data(), ITEM_LEN*UNION_SIZE); 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[Private-ID from OPRF+PSU]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
       
    return {vec_union_id, vec_Y_id};
}

  
}
#endif
