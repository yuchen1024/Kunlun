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
    PSI_card_sum = 4
};

namespace PSO{

using Serialization::operator<<; 
using Serialization::operator>>; 

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

// serialize pp to stream
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.ote_part; 
    fout << pp.mqrpmt_part; 

	return fout; 
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

// deserialize pp from stream
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
    fin >> pp.ote_part;
    fin >> pp.mqrpmt_part; 

	return fin; 
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
    fin >> pp; 
    fin.close(); 
}



namespace PSI{
void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::cout << "[mqRPMT-based PSI] Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);

    std::cout << "[mqRPMT-based PSI] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_Y, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}
std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::cout << "[mqRPMT-based PSI] Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);

    std::cout << "[mqRPMT-based PSI] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_intersection = ALSZOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI]: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return vec_intersection;
}
}

namespace PSU{

void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
        
    std::cout << "[mqRPMT-based PSU] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_Y, LEN); 
    
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "[mqRPMT-based PSU]: Sender side takes time = " 
            << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
        PrintSplitLine('-');
}

std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;
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
    std::cout << "[mqRPMT-based PSU]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return vec_union;
}

// support arbirary item (encode as uint8_t array)
void Send(NetIO &io, PP &pp, std::vector<std::vector<uint8_t>> &vec_Y, size_t ITEM_LEN, size_t ITEM_NUM) 
{
    auto start_time = std::chrono::steady_clock::now(); 
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;

    std::vector<block> vec_Block_Y(ITEM_NUM); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ITEM_NUM; i++){
        vec_Block_Y[i] = Hash::BytesToBlock(vec_Y[i]); 
    }
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Block_Y, ITEM_NUM);
        
    std::cout << "[mqRPMT-based PSU] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSendByteVector(io, pp.ote_part, vec_Y, ITEM_NUM); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSU]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
}

std::vector<std::vector<uint8_t>> Receive(NetIO &io, PP &pp, std::vector<std::vector<uint8_t>> &vec_X, 
                                          size_t ITEM_LEN, size_t ITEM_NUM) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;
     
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

    std::cout << "[mqRPMT-based PSU] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<std::vector<uint8_t>> vec_Y_diff; 
    vec_Y_diff = ALSZOTE::OnesidedReceiveByteVector(io, pp.ote_part, vec_indication_bit, ITEM_NUM); 
    std::vector<std::vector<uint8_t>> vec_union = vec_X; 
    for(auto i = 0; i < vec_Y_diff.size(); i++){
        vec_union.emplace_back(vec_Y_diff[i]);
    }
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSU]: Receiver side takes time = " 
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

    std::cout << "[mqRPMT-based PSI-card] Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);
        
    size_t CARDINALITY = 0; 
    for(auto i = 0; i < LEN; i++){
        CARDINALITY += vec_indication_bit[i]; 
    } 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI-card]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-');
        
    return CARDINALITY;
}

void Send(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSI-card] Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI-card]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
}
}

namespace PSIcardsum{
size_t Send(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);

    std::cout << "[mqRPMT-based PSI-card-sum] Phase 2: execute OTe >>>" << std::endl;
    std::vector<std::vector<uint8_t>> vec_result = ALSZOTE::ReceiveByteVector(io, pp.ote_part, vec_indication_bit, LEN); 
    std::vector<BigInt> vec_v(LEN); 

    size_t CARDINALITY = 0; 
    for(auto i = 0; i < LEN; i++){
        CARDINALITY += vec_indication_bit[i]; 
    }

    BigInt masked_SUM = bn_0; 
    for(auto i = 0; i < LEN; i++){
        vec_v[i].FromByteVector(vec_result[i]); 
        masked_SUM = (masked_SUM + vec_v[i]) % order; 
    }

    io.SendInteger(CARDINALITY);
    io.SendBigInt(masked_SUM);  
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 3: Sender  ===> (CARDINALITY, masked_SUM) ===> Receiver";
    std::cout << " [" << (sizeof(CARDINALITY) + BN_BYTE_LEN)/(1024*1024) << " MB]" << std::endl;

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI-card-sum]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return CARDINALITY;
}

std::tuple<size_t, BigInt> Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y, 
                                    std::vector<BigInt> &vec_v, size_t LEN) 
{
    std::vector<BigInt> vec_r = GenRandomBigIntVectorLessThan(LEN, order);
    BigInt mask = bn_0;
    for(auto i = 0; i < LEN; i++){
        mask = (mask + vec_r[i]) % order;   
    }

    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 1: execute mqRPMT >>>" << std::endl;
    
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);

    for(auto i = 0; i < LEN; i++){
        vec_v[i] =  (vec_v[i] + vec_r[i]) % order;   // v_i = r_i + v_i  
    } 

    std::vector<std::vector<uint8_t>> vec_m0(LEN); 
    std::vector<std::vector<uint8_t>> vec_m1(LEN); 
    
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        vec_m0[i] = vec_r[i].ToByteVector(); 
        vec_m1[i] = vec_v[i].ToByteVector();
    }

    std::cout << "[mqRPMT-based PSI-card-sum] Phase 2: execute OTe >>>" << std::endl;
    ALSZOTE::SendByteVector(io, pp.ote_part, vec_m0, vec_m1, LEN); 


    size_t CARDINALITY; 
    io.ReceiveInteger(CARDINALITY);
    BigInt SUM; 
    io.ReceiveBigInt(SUM);  
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 3: Receiver obtains (CARDINALITY, masked_SUM) from Sender" << std::endl;
    
    SUM = (SUM - mask) % order; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI-card-sum]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-');

    return {CARDINALITY, SUM}; 
}
}

}
#endif
