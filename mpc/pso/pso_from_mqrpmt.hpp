#ifndef KUNLUN_PSO_HPP_
#define KUNLUN_PSO_HPP_

#include "../rpmt/cwprf_mqrpmt.hpp"
#include "../ot/iknp_ote.hpp"
#include "../ot/alsz_ote.hpp"


/*
** implement PSU based on weak commutative PSU
*/

enum PSO_type{ 
    PSI = 1, 
    PSU = 2, 
    PSI_card = 3, 
    PSI_sum = 4
};

namespace PSO{

struct PP
{
    ALSZOTE::PP ote_part; 
    cwPRFmqRPMT::PP mqrpmt_part; 
};

PP Setup(std::string filter_type, size_t statistical_security_parameter)
{
    PP pp; 
    pp.ote_part = ALSZOTE::Setup(128); 
    pp.mqrpmt_part = cwPRFmqRPMT::Setup(filter_type, statistical_security_parameter); 
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

    fout << pp.ote_part; 
    fout << pp.mqrpmt_part; 
    
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
    fin >> pp.ote_part;
    fin >> pp.mqrpmt_part; 
    fin.close(); 
}

namespace PSI{
std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);

    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_intersection = ALSZOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return vec_intersection;
}

void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);

    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_Y, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}
}

namespace PSU{

void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
        
    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_Y, LEN); 
    
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "mqRPMT-based PSU: Sender side takes time = " 
            << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
        PrintSplitLine('-');
}

std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit(LEN); 
    vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);
       
    // flip the indication bit to get elements in Y\X
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        vec_indication_bit[i] ^= 0x01; 
    } 

    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_Y_diff = ALSZOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
    std::vector<block> vec_union = vec_X; 
    for(auto i = 0; i < vec_Y_diff.size(); i++){
        vec_union.emplace_back(vec_Y_diff[i]);
    }
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSU: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return vec_union;
}

// support arbirary item (encode as uint8_t array)
void Send(NetIO &io, PP &pp, std::vector<std::vector<uint8_t>> &vec_Y, size_t ITEM_LEN, size_t ITEM_NUM) 
{
    auto start_time = std::chrono::steady_clock::now(); 
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;

    std::vector<block> vec_Block_Y(ITEM_NUM); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ITEM_NUM; i++){
        vec_Block_Y[i] = Hash::BytesToBlock(vec_Y[i]); 
    }
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Block_Y, ITEM_NUM);
        
    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_Y, ITEM_LEN, ITEM_NUM); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSU: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
}

std::vector<std::vector<uint8_t>> 
Receive(NetIO &io, PP &pp, std::vector<std::vector<uint8_t>> &vec_X, size_t ITEM_LEN, size_t ITEM_NUM) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
     
    std::vector<block> vec_Block_Y(ITEM_NUM); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ITEM_NUM; i++){
        vec_Block_Y[i] = Hash::BytesToBlock(vec_X[i]); 
    }
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_Block_Y, ITEM_NUM);
       
    // flip the indication bit to get elements in Y\X
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ITEM_NUM; i++){
        vec_indication_bit[i] ^= 0x01; 
    } 

    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<std::vector<uint8_t>> vec_Y_diff; 
    vec_Y_diff = ALSZOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, ITEM_LEN, ITEM_NUM); 
    std::vector<std::vector<uint8_t>> vec_union = vec_X; 
    for(auto i = 0; i < vec_Y_diff.size(); i++){
        vec_union.emplace_back(vec_Y_diff[i]);
    }
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSU: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return vec_union;
}



}

namespace PSIcard{
size_t Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');

    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);
        
    //auto start_time_1 = std::chrono::steady_clock::now(); 
     size_t CARDINALITY = 0; 
    // flip the indication bit to get elements in Y\X
    for(auto i = 0; i < LEN; i++){
        CARDINALITY += vec_indication_bit[i]; 
    } 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-cardinality: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-');
        
    return CARDINALITY;
}

void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-cardinality: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
}
}

namespace PSIsum{
int64_t Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);

    std::cout << "Phase 2: execute OTe >>>" << std::endl;
    std::vector<block> vec_result = ALSZOTE::Receive(io, pp.ote_part, vec_indication_bit, LEN); 
    std::vector<int64_t> vec_v(LEN); 
    int64_t SUM = 0; 
    for(auto i = 0; i < LEN; i++){
        vec_v[i] = Block::BlockToInt64(vec_result[i]); 
        SUM += vec_v[i]; 
    }

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-sum: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return SUM;
}

void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, std::vector<int64_t> &vec_label, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
    
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
    // get the intersection X \cup Y via one-sided OT from receiver

    std::vector<int64_t> vec_r = GenRandomIntegerVectorLessThan(LEN, 100);
    
    std::vector<int64_t> vec_v = vec_label; 
    vec_r[LEN-1] = 0; 
    for(auto i = 0; i < LEN-1; i++){
        vec_r[LEN-1] += vec_r[i];  
    } 
    vec_r[LEN-1] = -vec_r[LEN-1];    // generate r_i such that the sum is zero 
    
    for(auto i = 0; i < LEN; i++){
        vec_v[i] += vec_r[i];   // r_i + v_i  
    } 

    std::vector<block> vec_m0(LEN); 
    std::vector<block> vec_m1(LEN); 
    
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        vec_m0[i] = Block::MakeBlock(0, vec_r[i]); 
        vec_m1[i] = Block::MakeBlock(0, vec_v[i]);
    }

    std::cout << "Phase 2: execute OTe >>>" << std::endl;
    ALSZOTE::Send(io, pp.ote_part, vec_m0, vec_m1, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-sum: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-');
}
}

}
#endif
