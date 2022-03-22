#ifndef KUNLUN_PSO_HPP_
#define KUNLUN_PSO_HPP_

#include "../rpmt/cwprf_mqrpmt.hpp"
#include "../ot/iknp_ote.hpp"


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
    IKNPOTE::PP ote_part; 
    cwPRFmqRPMT::PP mqrpmt_part; 
};

PP Setup(std::string filter_type, size_t lambda)
{
    PP pp; 
    pp.ote_part = IKNPOTE::Setup(); 
    pp.mqrpmt_part = cwPRFmqRPMT::Setup(filter_type, lambda); 
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

    IKNPOTE::SerializePP(pp.ote_part, fout); 
    cwPRFmqRPMT::SerializePP(pp.mqrpmt_part, fout); 
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
    IKNPOTE::DeserializePP(pp.ote_part, fin); 
    cwPRFmqRPMT::DeserializePP(pp.mqrpmt_part, fin); 
    fin.close(); 
}

std::vector<block> PSIServer(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);

    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_intersection = IKNPOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI: Server side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return vec_intersection;
}

void PSIClient(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
    // get the intersection X \cup Y via one-sided OT from receiver
    IKNPOTE::OnesidedSend(io, pp.ote_part, vec_Y, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI: Client side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}


std::vector<block> PSUServer(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);
    // flip the indication bit to get elements in Y\X
    for(auto i = 0; i < LEN; i++){
        vec_indication_bit[i] = 1 - vec_indication_bit[i]; 
    } 
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_coset = IKNPOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
    std::vector<block> vec_union = vec_X; 
    for(auto i = 0; i < vec_coset.size(); i++)
        vec_union.emplace_back(vec_coset[i]); 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSU: Server side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return vec_union;
}

void PSUClient(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
    // get the intersection X \cup Y via one-sided OT from receiver
    IKNPOTE::OnesidedSend(io, pp.ote_part, vec_Y, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSU: Client side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

size_t PSIcardServer(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    size_t CARDINALITY = 0; 
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);
    // flip the indication bit to get elements in Y\X
    for(auto i = 0; i < LEN; i++){
        CARDINALITY += vec_indication_bit[i]; 
    } 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-cardinality: Server side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return CARDINALITY;
}

void PSIcardClient(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_Y, LEN);
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-cardinality: Client side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

int64_t PSIsumServer(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);

    std::vector<block> vec_result = IKNPOTE::Receive(io, pp.ote_part, vec_indication_bit, LEN); 
    std::vector<int64_t> vec_v(LEN); 
    int64_t SUM = 0; 
    for(auto i = 0; i < LEN; i++){
        vec_v[i] = Block::BlockToInt64(vec_result[i]); 
        SUM += vec_v[i]; 
    }

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-sum: Server side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return SUM;
}

void PSIsumClient(NetIO &io, PP &pp, std::vector<block> &vec_Y, std::vector<int64_t> &vec_label, size_t LEN) 
{
    auto start_time = std::chrono::steady_clock::now(); 

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
    
    for(auto i = 0; i < LEN; i++){
        vec_m0[i] = Block::MakeBlock(0, vec_r[i]); 
        vec_m1[i] = Block::MakeBlock(0, vec_v[i]);
    }

    IKNPOTE::Send(io, pp.ote_part, vec_m0, vec_m1, LEN); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "mqRPMT-based PSI-sum: Client side takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}


}
#endif
