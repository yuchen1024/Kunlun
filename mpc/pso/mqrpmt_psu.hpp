#ifndef KUNLUN_MQRPMT_PSU_HPP_
#define KUNLUN_MQRPMT_PSU_HPP_

#include "../rpmt/cwprf_mqrpmt.hpp"
#include "../ot/alsz_ote.hpp"


/*
** implement mqRPMT-based PSU
*/

namespace mqRPMTPSU{

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    ALSZOTE::PP ote_part; 
    cwPRFmqRPMT::PP mqrpmt_part; 

    size_t LOG_SENDER_LEN; 
    size_t LOG_RECEIVER_LEN; 
    size_t SENDER_LEN; 
    size_t RECEIVER_LEN; 
};

PP Setup(std::string filter_type, 
        size_t computational_security_parameter, 
        size_t statistical_security_parameter, 
        size_t LOG_SENDER_LEN, size_t LOG_RECEIVER_LEN)
{
    PP pp; 
    pp.ote_part = ALSZOTE::Setup(computational_security_parameter);

    // always having receiver plays the role of server, sender play the role of client
    pp.mqrpmt_part = cwPRFmqRPMT::Setup(filter_type, statistical_security_parameter, 
                                        LOG_RECEIVER_LEN, LOG_SENDER_LEN);

    pp.LOG_SENDER_LEN = LOG_SENDER_LEN; 
    pp.LOG_RECEIVER_LEN = LOG_RECEIVER_LEN; 
    pp.SENDER_LEN = size_t(pow(2, pp.LOG_SENDER_LEN));
    pp.RECEIVER_LEN = size_t(pow(2, pp.LOG_RECEIVER_LEN)); 

    return pp; 
}

// serialize pp to stream
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.ote_part; 
    fout << pp.mqrpmt_part; 

    fout << pp.LOG_SENDER_LEN; 
    fout << pp.LOG_RECEIVER_LEN; 
    fout << pp.SENDER_LEN; 
    fout << pp.RECEIVER_LEN; 

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

    fin >> pp.LOG_SENDER_LEN; 
    fin >> pp.LOG_RECEIVER_LEN; 
    fin >> pp.SENDER_LEN; 
    fin >> pp.RECEIVER_LEN; 

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

void Send(NetIO &io, PP &pp, std::vector<block> &vec_X) 
{
    if(vec_X.size() != pp.SENDER_LEN){
        std::cerr << "|X| does not match public parameter" << std::endl; 
        exit(1); 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_X);
        
    std::cout << "[mqRPMT-based PSU] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_X, pp.SENDER_LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSU]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
}

std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y) 
{
    if(vec_Y.size() != pp.RECEIVER_LEN){
        std::cerr << "|Y| does not match public parameter" << std::endl; 
        exit(1); 
    }

    auto start_time = std::chrono::steady_clock::now();    
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_Y);
       
    // flip the indication bit to get elements in Y\X
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < vec_indication_bit.size(); i++){
        vec_indication_bit[i] ^= 0x01; 
    } 

    std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_X_diff = ALSZOTE::OnesidedReceive(io, pp.ote_part, 
                                                             vec_indication_bit, vec_indication_bit.size()); 
    std::vector<block> vec_union = vec_Y; 
    for(auto i = 0; i < vec_X_diff.size(); i++){
        vec_union.emplace_back(vec_X_diff[i]);
    }
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSU]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return vec_union;
}

// support arbirary item (encode as uint8_t array)
void Send(NetIO &io, PP &pp, std::vector<std::vector<uint8_t>> &vec_X, size_t ITEM_LEN) 
{
    if(vec_X.size() != pp.SENDER_LEN){
        std::cerr << "|X| does not match public parameter" << std::endl; 
        exit(1); 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;

    std::vector<block> vec_Block_X(pp.SENDER_LEN); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < vec_X.size(); i++){
        vec_Block_X[i] = Hash::BytesToBlock(vec_X[i]); 
    }
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Block_X);
        
    std::cout << "[mqRPMT-based PSU] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSendByteVector(io, pp.ote_part, vec_X, vec_X.size()); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSU]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');
}

std::vector<std::vector<uint8_t>> Receive(NetIO &io, PP &pp, std::vector<std::vector<uint8_t>> &vec_Y, size_t ITEM_LEN) 
{
    if(vec_Y.size() != pp.RECEIVER_LEN){
        std::cerr << "|Y| does not match public parameter" << std::endl; 
        exit(1); 
    }
    
    auto start_time = std::chrono::steady_clock::now();     
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSU] Phase 1: execute mqRPMT >>>" << std::endl;
     
    std::vector<block> vec_Block_Y(pp.RECEIVER_LEN); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < vec_Y.size(); i++){
        vec_Block_Y[i] = Hash::BytesToBlock(vec_Y[i]); 
    }
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_Block_Y);
       
    // flip the indication bit to get elements in Y\X
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < vec_indication_bit.size(); i++){
        vec_indication_bit[i] ^= 0x01; 
    } 

    std::cout << "[mqRPMT-based PSU] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<std::vector<uint8_t>> vec_X_diff; 
    vec_X_diff = ALSZOTE::OnesidedReceiveByteVector(io, pp.ote_part, vec_indication_bit, vec_indication_bit.size()); 
    std::vector<std::vector<uint8_t>> vec_union = vec_Y; 
    for(auto i = 0; i < vec_X_diff.size(); i++){
        vec_union.emplace_back(vec_X_diff[i]);
    }
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSU]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return vec_union;
}

}
#endif
