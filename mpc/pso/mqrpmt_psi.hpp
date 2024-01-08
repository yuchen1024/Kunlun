#ifndef KUNLUN_MQRPMT_PSI_HPP_
#define KUNLUN_MQRPMT_PSI_HPP_

#include "../rpmt/cwprf_mqrpmt.hpp"
#include "../ot/alsz_ote.hpp"


/*
** implement mqRPMT-based PSI 
*/


namespace mqRPMTPSI{

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    ALSZOTE::PP ote_part; 
    cwPRFmqRPMT::PP mqrpmt_part; 

    size_t LOG_SENDER_ITEM_NUM; 
    size_t LOG_RECEIVER_ITEM_NUM; 
    size_t SENDER_ITEM_NUM; 
    size_t RECEIVER_ITEM_NUM; 
};


PP Setup(size_t computational_security_parameter, size_t statistical_security_parameter, size_t LOG_SENDER_ITEM_NUM, size_t LOG_RECEIVER_ITEM_NUM)
{
    PP pp; 
    pp.ote_part = ALSZOTE::Setup(computational_security_parameter);

    // always having receiver plays the role of server, sender play the role of client
    pp.mqrpmt_part = cwPRFmqRPMT::Setup(statistical_security_parameter, LOG_RECEIVER_ITEM_NUM, LOG_SENDER_ITEM_NUM);

    pp.LOG_SENDER_ITEM_NUM = LOG_SENDER_ITEM_NUM; 
    pp.LOG_RECEIVER_ITEM_NUM = LOG_RECEIVER_ITEM_NUM; 
    pp.SENDER_ITEM_NUM = size_t(pow(2, pp.LOG_SENDER_ITEM_NUM));
    pp.RECEIVER_ITEM_NUM = size_t(pow(2, pp.LOG_RECEIVER_ITEM_NUM)); 

    return pp; 
}

// serialize pp to stream
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.ote_part; 
    fout << pp.mqrpmt_part; 

    
    fout << pp.LOG_SENDER_ITEM_NUM; 
    fout << pp.LOG_RECEIVER_ITEM_NUM; 
    fout << pp.SENDER_ITEM_NUM; 
    fout << pp.RECEIVER_ITEM_NUM; 

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

    fin >> pp.LOG_SENDER_ITEM_NUM; 
    fin >> pp.LOG_RECEIVER_ITEM_NUM; 
    fin >> pp.SENDER_ITEM_NUM; 
    fin >> pp.RECEIVER_ITEM_NUM; 

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
    if(vec_X.size() != pp.SENDER_ITEM_NUM){
        std::cerr << "|X| does not match public parameter" << std::endl; 
        exit(1); // EXIT_FAILURE  
    }

    auto start_time = std::chrono::steady_clock::now(); 
    std::cout << "[mqRPMT-based PSI] Phase 1: execute mqRPMT >>>" << std::endl;
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_X);

    std::cout << "[mqRPMT-based PSI] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    ALSZOTE::OnesidedSend(io, pp.ote_part, vec_X, vec_X.size()); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

std::vector<block> Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y) 
{
    if(vec_Y.size() != pp.RECEIVER_ITEM_NUM){
        std::cerr << "|Y| does not match public parameter" << std::endl; 
        exit(1); // EXIT_FAILURE  
    }

    auto start_time = std::chrono::steady_clock::now(); 
    std::cout << "[mqRPMT-based PSI] Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_Y);

    std::cout << "[mqRPMT-based PSI] Phase 2: execute one-sided OTe >>>" << std::endl;
    // get the intersection X \cup Y via one-sided OT from receiver
    std::vector<block> vec_intersection = ALSZOTE::OnesidedReceive(io, pp.ote_part, 
                                                vec_indication_bit, vec_indication_bit.size()); 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI]: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    return vec_intersection;
}

}

#endif
