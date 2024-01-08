#ifndef KUNLUN_MQRPMT_PSI_CARD_SUM_HPP_
#define KUNLUN_MQRPMT_PSI_CARD_SUM_HPP_

#include "../rpmt/cwprf_mqrpmt.hpp"
#include "../ot/alsz_ote.hpp"


/*
** implement mqRPMT-based PSI-card-sum 
*/

namespace mqRPMTPSIcardsum{

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
    size_t LOG_SUM_BOUND; // binary length of SUM_BOUND
    size_t LOG_VALUE_BOUND; // binary length of VALUE_BOUND
};

PP Setup(size_t computational_security_parameter, size_t statistical_security_parameter, 
         size_t LOG_SENDER_ITEM_NUM, size_t LOG_RECEIVER_ITEM_NUM, 
         size_t LOG_SUM_BOUND, size_t LOG_VALUE_BOUND)
{
    PP pp; 
    pp.ote_part = ALSZOTE::Setup(computational_security_parameter);

    // always having receiver plays the role of server, sender play the role of client
    pp.mqrpmt_part = cwPRFmqRPMT::Setup(statistical_security_parameter, LOG_RECEIVER_ITEM_NUM, LOG_SENDER_ITEM_NUM);

    pp.LOG_SENDER_ITEM_NUM = LOG_SENDER_ITEM_NUM;
    pp.LOG_RECEIVER_ITEM_NUM = LOG_RECEIVER_ITEM_NUM; 

    pp.SENDER_ITEM_NUM = size_t(pow(2, pp.LOG_SENDER_ITEM_NUM));
    pp.RECEIVER_ITEM_NUM = size_t(pow(2, pp.LOG_RECEIVER_ITEM_NUM)); 

    if(LOG_SUM_BOUND%8 != 0){
        std::cerr << "LOG_SUM_BOUND must be mulitple of 8" << std::endl;
        exit(1); // EXIT_FAILURE  
    }
    pp.LOG_SUM_BOUND = LOG_SUM_BOUND; 
    pp.LOG_VALUE_BOUND = LOG_VALUE_BOUND; 

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
    fout << pp.LOG_SUM_BOUND; 
    fout << pp.LOG_VALUE_BOUND;

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
    fin >> pp.LOG_SUM_BOUND; // must be divided by 8
    fin >> pp.LOG_VALUE_BOUND;

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
        exit(1); // EXIT_FAILURE 
    }
    fin >> pp; 
    fin.close(); 
}


std::tuple<size_t, BigInt> Send(NetIO &io, PP &pp, std::vector<block> &vec_X, std::vector<BigInt> &vec_v) 
{
    if(vec_X.size() != pp.SENDER_ITEM_NUM){
        std::cerr << "|X| does not match public parameter" << std::endl; 
        exit(1); // EXIT_FAILURE 
    }
    
    BigInt VALUE_BOUND = BigInt(pow(2, pp.LOG_VALUE_BOUND)); 
    BigInt SUM_BOUND = BigInt(pow(2, pp.LOG_SUM_BOUND)); 
    std::vector<BigInt> vec_r = GenRandomBigIntVectorLessThan(pp.SENDER_ITEM_NUM, SUM_BOUND);
    
    BigInt mask = bn_0;
    for(auto i = 0; i < vec_r.size(); i++){
        mask += vec_r[i];   
    }

    auto start_time = std::chrono::steady_clock::now(); 
        
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 1: execute mqRPMT >>>" << std::endl;
    
    cwPRFmqRPMT::Client(io, pp.mqrpmt_part, vec_X);

    for(auto i = 0; i < pp.SENDER_ITEM_NUM; i++){
        vec_v[i] =  (vec_v[i] + vec_r[i]) % SUM_BOUND;   // v_i = r_i + v_i  
    } 

    std::vector<std::vector<uint8_t>> vec_m0(pp.SENDER_ITEM_NUM); 
    std::vector<std::vector<uint8_t>> vec_m1(pp.SENDER_ITEM_NUM); 
    
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SENDER_ITEM_NUM; i++){
        vec_m0[i] = vec_r[i].ToByteVector(pp.LOG_SUM_BOUND/8); 
        vec_m1[i] = vec_v[i].ToByteVector(pp.LOG_SUM_BOUND/8);
    }

    std::cout << "[mqRPMT-based PSI-card-sum] Phase 2: execute OTe >>>" << std::endl;
    ALSZOTE::SendByteVector(io, pp.ote_part, vec_m0, vec_m1, pp.SENDER_ITEM_NUM); 

    size_t CARDINALITY; 
    io.ReceiveInteger(CARDINALITY);
    BigInt SUM; 
    io.ReceiveBigInt(SUM, pp.LOG_SUM_BOUND/8);  
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 3: Sender obtains (CARDINALITY, masked_SUM) from Receiver" << std::endl;
    
    SUM = (SUM - mask) % SUM_BOUND; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI-card-sum]: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-');

    return {CARDINALITY, SUM}; 
}

size_t Receive(NetIO &io, PP &pp, std::vector<block> &vec_Y) 
{
    if(vec_Y.size() != pp.RECEIVER_ITEM_NUM){
        std::cerr << "|Y| does not match public parameter" << std::endl; 
        exit(1); // EXIT_FAILURE 
    }

    auto start_time = std::chrono::steady_clock::now();     
    PrintSplitLine('-');
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 1: execute mqRPMT >>>" << std::endl;
    std::vector<uint8_t> vec_indication_bit = cwPRFmqRPMT::Server(io, pp.mqrpmt_part, vec_Y);

    std::cout << "[mqRPMT-based PSI-card-sum] Phase 2: execute OTe >>>" << std::endl;
    std::vector<std::vector<uint8_t>> vec_result = ALSZOTE::ReceiveByteVector(io, pp.ote_part, 
        vec_indication_bit, vec_indication_bit.size());

    std::vector<BigInt> vec_v(pp.RECEIVER_ITEM_NUM); 

    size_t CARDINALITY = 0; 
    for(auto i = 0; i < vec_indication_bit.size(); i++){
        CARDINALITY += vec_indication_bit[i]; 
    }

    BigInt masked_SUM = bn_0; 
    BigInt SUM_BOUND = BigInt(pow(2, pp.LOG_SUM_BOUND)); 
    for(auto i = 0; i < vec_v.size(); i++){
        vec_v[i].FromByteVector(vec_result[i]); 
        masked_SUM += vec_v[i];  
    }
    masked_SUM = masked_SUM % SUM_BOUND;

    io.SendInteger(CARDINALITY);

    io.SendBigInt(masked_SUM, pp.LOG_SUM_BOUND/8);  
    std::cout << "[mqRPMT-based PSI-card-sum] Phase 3: Receiver  ===> (CARDINALITY, masked_SUM) ===> Sender";
    std::cout << " [" << (sizeof(CARDINALITY) + pp.LOG_SUM_BOUND/8)/(1024*1024) << " MB]" << std::endl;

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "[mqRPMT-based PSI-card-sum]: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-');

    return CARDINALITY;
}

}
#endif
