#ifndef KUNLUN_PID_HPP_
#define KUNLUN_PID_HPP_

#include "../pso/pso.hpp"
#include "../pid/private_id.hpp"


/*
** implement Private-ID based on OPRF and PSU
*/

namespace PID{

struct PP
{
    MPOPRF::PP oprf_part; 
    PSO::PP pso_part; 
};

PP Setup(std::string filter_type, size_t lambda)
{
    PP pp; 
    pp.pso_part = PSO::Setup(filter_type, lambda); 
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

    fout << pp.pso_part; 
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
    fin >> pp.pso_part;
    fin >> pp.mqrpmt_part; 
    fin.close(); 
}

namespace PID{
    std::vector<block> Send(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN)
    {
        auto start_time = std::chrono::steady_clock::now(); 
        
        PrintSplitLine('-');
        std::cout << "Phase 1: compute sender's PID >>>" << std::endl;


       
        // flip the indication bit to get elements in Y\X
        #pragma omp parallel for
        for(auto i = 0; i < LEN; i++){
            vec_indication_bit[i] ^= 0x01; 
        } 

        std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
        // get the intersection X \cup Y via one-sided OT from receiver
        std::vector<block> vec_Y_diff = ALSZOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
        std::vector<block> vec_union = vec_X; 
        for(auto i = 0; i < vec_Y_diff.size(); i++)
            vec_union.emplace_back(vec_Y_diff[i]);
    
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "mqRPMT-based PSU: Receiver side takes time = " 
            << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
        PrintSplitLine('-');

        return vec_union;
    }



    std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
    {
        auto start_time = std::chrono::steady_clock::now(); 
        
        PrintSplitLine('-');
        std::cout << "Phase 1: execute mqRPMT >>>" << std::endl;
        std::vector<uint8_t> vec_indication_bit(LEN); 
        vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_X, LEN);
       
        // flip the indication bit to get elements in Y\X
        #pragma omp parallel for
        for(auto i = 0; i < LEN; i++){
            vec_indication_bit[i] ^= 0x01; 
        } 

        std::cout << "Phase 2: execute one-sided OTe >>>" << std::endl;
        // get the intersection X \cup Y via one-sided OT from receiver
        std::vector<block> vec_Y_diff = ALSZOTE::OnesidedReceive(io, pp.ote_part, vec_indication_bit, LEN); 
        std::vector<block> vec_union = vec_X; 
        for(auto i = 0; i < vec_Y_diff.size(); i++)
            vec_union.emplace_back(vec_Y_diff[i]);
    
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "mqRPMT-based PSU: Receiver side takes time = " 
            << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
        PrintSplitLine('-');

        return vec_union;
    }

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
}




}
#endif
