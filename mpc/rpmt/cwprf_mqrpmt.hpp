#ifndef KUNLUN_CWPRF_MQRPMT_HPP_
#define KUNLUN_CWPRF_MQRPMT_HPP_

#include "../../crypto/ec_group.hpp"
#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../crypto/prg.hpp"
#include "../../crypto/block.hpp"
#include "../../netio/stream_channel.hpp"
#include "../../filter/bloom_filter.hpp"



/*
** implement multi-query RPMT based on weak commutative PRF
** cuckoo filter is not gurantteed to be safe here, cause the filter may reveal the order of X
*/

namespace cwPRFmqRPMT{

using Serialization::operator<<; 
using Serialization::operator>>; 

const size_t BATCH_SIZE = 8; // used for pipelining optimization

struct PP
{
    bool malicious = false;
    std::string filter_type; // shuffle, bloom
    size_t statistical_security_parameter; // default=40 
    
    size_t SERVER_LOG_LEN; 
    size_t SERVER_LEN; 
    size_t CLIENT_LOG_LEN; 
    size_t CLIENT_LEN; 
};

// seriazlize
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.filter_type;
    fout << pp.statistical_security_parameter; 
    fout << pp.SERVER_LOG_LEN;
    fout << pp.SERVER_LEN; 
    fout << pp.CLIENT_LOG_LEN;
    fout << pp.CLIENT_LEN; 

    return fout; 
}

// load pp from file
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
    fin >> pp.filter_type;
    fin >> pp.statistical_security_parameter; 

    fin >> pp.SERVER_LOG_LEN;
    fin >> pp.SERVER_LEN;
    fin >> pp.CLIENT_LOG_LEN;
    fin >> pp.CLIENT_LEN;

    return fin; 
}

PP Setup(std::string filter_type, 
         size_t statistical_security_parameter, 
         size_t SERVER_LOG_LEN, 
         size_t CLIENT_LOG_LEN)
{
    PP pp; 
    pp.filter_type = filter_type; 
    pp.statistical_security_parameter = statistical_security_parameter; 
    pp.SERVER_LOG_LEN = SERVER_LOG_LEN; 
    pp.SERVER_LEN = size_t(pow(2, pp.SERVER_LOG_LEN)); 
    pp.CLIENT_LOG_LEN = CLIENT_LOG_LEN; 
    pp.CLIENT_LEN = size_t(pow(2, pp.CLIENT_LOG_LEN)); 
    return pp; 
}

void SavePP(PP &pp, std::string pp_filename)
{
    std::ofstream fout; 
    fout.open(pp_filename, std::ios::binary); 
    if(!fout){
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << pp; 
    fout.close(); 
}

void FetchPP(PP &pp, std::string pp_filename)
{
    std::ifstream fin; 
    fin.open(pp_filename, std::ios::binary); 
    if(!fin){
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> pp; 
    fin.close(); 
}

std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<block> &vec_Y)
{
    if(pp.SERVER_LEN != vec_Y.size()){
        std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
        exit(1);  
    }

    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 
    
    BigInt k1 = GenRandomBigIntLessThan(order); // pick a key k1

    std::vector <ECPoint> vec_Fk1_Y(pp.SERVER_LEN);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        vec_Fk1_Y[i] = Hash::BlockToECPoint(vec_Y[i]) * k1; // H(x_i)^k1
    }

    io.SendECPoints(vec_Fk1_Y.data(), pp.SERVER_LEN); 
    
    std::cout <<"cwPRF-based mqRPMT [step 1]: Server ===> F_k1(y_i) ===> Client";
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN * pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    std::vector<ECPoint> vec_Fk2_X(pp.CLIENT_LEN); 
    io.ReceiveECPoints(vec_Fk2_X.data(), pp.CLIENT_LEN);

    std::vector<ECPoint> vec_Fk1k2_X(pp.CLIENT_LEN); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < pp.CLIENT_LEN; i++){ 
        vec_Fk1k2_X[i] = vec_Fk2_X[i] * k1; 
    }

    // compute the indication bit vector
    std::vector<uint8_t> vec_indication_bit(pp.CLIENT_LEN);

    if(pp.filter_type == "shuffle"){
        std::vector<ECPoint> vec_Fk2k1_Y(pp.SERVER_LEN);
        io.ReceiveECPoints(vec_Fk2k1_Y.data(), pp.SERVER_LEN);
        std::unordered_set<ECPoint, ECPointHash> S;
        for(auto i = 0; i < pp.SERVER_LEN; i++){
            S.insert(vec_Fk2k1_Y[i]); 
        }
        for(auto i = 0; i < pp.CLIENT_LEN; i++){
            if(S.find(vec_Fk1k2_X[i]) == S.end()) vec_indication_bit[i] = 0;  
            else vec_indication_bit[i] = 1;
        }
    }

    if(pp.filter_type == "bloom"){
        BloomFilter filter; 
        // get the size of filter 
        size_t filter_size = filter.ObjectSize();
        io.ReceiveInteger(filter_size);
        // get the content of filter
        char *buffer = new char[filter_size]; 
        io.ReceiveBytes(buffer, filter_size);
        
        // reconstruct bloom filter  
        filter.ReadObject(buffer);  
        delete[] buffer; 

        vec_indication_bit = filter.Contain(vec_Fk1k2_X); 
    } 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "cwPRF-mqRPMT: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-'); 

    return vec_indication_bit; 
}

void Client(NetIO &io, PP &pp, std::vector<block> &vec_X) 
{    
    if(pp.CLIENT_LEN != vec_X.size()){
        std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
        exit(1);  
    }
    
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 

    BigInt k2 = GenRandomBigIntLessThan(order); // pick a key

    std::vector<ECPoint> vec_Fk2_X(pp.CLIENT_LEN); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < pp.CLIENT_LEN; i++){
        vec_Fk2_X[i] = Hash::BlockToECPoint(vec_X[i]) * k2; // H(x_i)^k2
    } 

    // first receive incoming data
    std::vector<ECPoint> vec_Fk1_Y(pp.SERVER_LEN);
    io.ReceiveECPoints(vec_Fk1_Y.data(), pp.SERVER_LEN); // receive Fk1_Y from Server

    // then send
    io.SendECPoints(vec_Fk2_X.data(), pp.CLIENT_LEN);

    std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> F_k2(x_i) ===> Server"; 
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*pp.CLIENT_LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*pp.CLIENT_LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    std::vector<ECPoint> vec_Fk2k1_Y(pp.SERVER_LEN);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        vec_Fk2k1_Y[i] = vec_Fk1_Y[i] * k2; 
    }

    // permutation
    if(pp.filter_type == "shuffle"){
        std::random_shuffle(vec_Fk2k1_Y.begin(), vec_Fk2k1_Y.end());
        io.SendECPoints(vec_Fk2k1_Y.data(), pp.SERVER_LEN); 
        std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> Permutation(F_k2k1(y_i)) ===> Server"; 
        #ifdef ECPOINT_COMPRESSED
            std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN * pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
        #else
            std::cout << " [" << (double)POINT_BYTE_LEN*pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
        #endif
    }

    // generate and send bloom filter
    if(pp.filter_type == "bloom"){

        BloomFilter filter(vec_Fk2k1_Y.size(), pp.statistical_security_parameter);

        filter.Insert(vec_Fk2k1_Y);

        size_t filter_size = filter.ObjectSize(); 
        io.SendInteger(filter_size);

        char *buffer = new char[filter_size]; 
        filter.WriteObject(buffer);
        io.SendBytes(buffer, filter_size); 
        std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> BloomFilter(F_k2k1(y_i)) ===> Server";
        std::cout << " [" << (double)filter_size/(1024*1024) << " MB]" << std::endl;

        delete[] buffer; 
    } 
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "cwPRF-mqRPMT: Client side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

        
    PrintSplitLine('-'); 
}


// std::vector<uint8_t> BatchServer(NetIO &io, PP &pp, std::vector<block> &vec_Y)
// {
//     if(pp.LEN != vec_X.size()){
//         std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
//         exit(1);  
//     }

//     PrintSplitLine('-'); 
//     auto start_time = std::chrono::steady_clock::now(); 
    
//     BigInt k1 = GenRandomBigIntLessThan(order); // pick a key k1

//     std::vector<ECPoint> vec_Fk1_Y(LEN);
//     std::vector<ECPoint> vec_Fk2_X(LEN); 
//     std::vector<ECPoint> vec_Fk1k2_X(LEN); 

//     size_t TASK_NUM = LEN/BATCH_SIZE;
//     size_t TASK_INDEX = 0;

//     #pragma omp parallel for num_threads(thread_count)
//     for(auto i = 0; i < LEN; i += BATCH_SIZE)
//     {
//         #pragma omp parallel for num_threads(thread_count)
//         for(auto j = 0; j < BATCH_SIZE; j++){
//             vec_Fk1_Y[i+j] = Hash::BlockToECPoint(vec_Y[i+j]) * k1; // H(x_i)^k1
//         }
//     }

//     io.SendECPoints(vec_Fk1_Y.data(), LEN); 

//     std::cout <<"cwPRF-based mqRPMT [step 1]: Server ===> F_k1(y_i) ===> Client";
//     #ifdef ECPOINT_COMPRESSED
//         std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
//     #else
//         std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
//     #endif

//     io.ReceiveECPoints(vec_Fk2_X.data(), LEN);
//     #pragma omp parallel for num_threads(thread_count)
//     for(auto i = 0; i < LEN; i += BATCH_SIZE)
//     {
//         #pragma omp parallel for num_threads(thread_count)
//         for(auto j = 0; j < BATCH_SIZE; j++){ 
//             vec_Fk1k2_X[i+j] = vec_Fk2_X[i+j] * k1; 
//         }
//     }

    
//     // compute the indication bit vector
//     std::vector<uint8_t> vec_indication_bit(LEN);

//     if(pp.filter_type == "shuffle"){
//         std::vector<ECPoint> vec_Fk2k1_Y(LEN);
//         io.ReceiveECPoints(vec_Fk2k1_Y.data(), LEN);
//         std::unordered_set<ECPoint, ECPointHash> S;
//         for(auto i = 0; i < LEN; i++){
//             S.insert(vec_Fk2k1_Y[i]); 
//         }
//         for(auto i = 0; i < LEN; i++){
//             if(S.find(vec_Fk1k2_X[i]) == S.end()) vec_indication_bit[i] = 0;  
//             else vec_indication_bit[i] = 1;
//         }
//     }

//     if(pp.filter_type == "bloom"){
//         BloomFilter filter; 
//         // get the size of filter 
//         size_t filter_size = filter.ObjectSize();
//         io.ReceiveInteger(filter_size);
//         // get the content of filter
//         char *buffer = new char[filter_size]; 
//         io.ReceiveBytes(buffer, filter_size);
        
//         // reconstruct bloom filter  
//         filter.ReadObject(buffer);  
//         delete[] buffer; 

//         vec_indication_bit = filter.Contain(vec_Fk1k2_X); 
//     } 

//     auto end_time = std::chrono::steady_clock::now(); 
//     auto running_time = end_time - start_time;
//     std::cout << "cwPRF-mqRPMT: Server side takes time = " 
//               << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
//     PrintSplitLine('-'); 

//     return vec_indication_bit; 
// }

// void BatchClient(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
// {    
//     PrintSplitLine('-'); 

//     auto start_time = std::chrono::steady_clock::now(); 

//     BigInt k2 = GenRandomBigIntLessThan(order); // pick a key

//     std::vector<ECPoint> vec_Fk2_X(LEN); 
//     std::vector<ECPoint> vec_Fk1_Y(LEN);
//     std::vector<ECPoint> vec_Fk2k1_Y(LEN);

//     #pragma omp parallel for num_threads(thread_count)
//     for(auto i = 0; i < LEN; i += BATCH_SIZE)
//     {
//         #pragma omp parallel for num_threads(thread_count)
//         for(auto j = 0; j < BATCH_SIZE; j++){
//             vec_Fk2_X[i+j] = Hash::BlockToECPoint(vec_X[i+j]) * k2; // H(x_i)^k2
//         } 
//     }

//     io.ReceiveECPoints(vec_Fk1_Y.data(), LEN); // receive Fk1_Y from Server

//     io.SendECPoints(vec_Fk2_X.data(), LEN);

//     std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> F_k2(x_i) ===> Server"; 
//     #ifdef ECPOINT_COMPRESSED
//         std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
//     #else
//         std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
//     #endif

//     #pragma omp parallel for num_threads(thread_count)
//     for(auto i = 0; i < LEN; i += BATCH_SIZE)
//     {        
//         #pragma omp parallel for num_threads(thread_count)
//         for(auto j = 0; j < BATCH_SIZE; j++){
//             vec_Fk2k1_Y[i+j] = vec_Fk1_Y[i+j] * k2; 
//         } 
//     } 


//     // permutation
//     if(pp.filter_type == "shuffle"){
//         std::random_shuffle(vec_Fk2k1_Y.begin(), vec_Fk2k1_Y.end());
//         io.SendECPoints(vec_Fk2k1_Y.data(), LEN); 
//         std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> Permutation(F_k2k1(y_i)) ===> Server"; 
//         #ifdef ECPOINT_COMPRESSED
//             std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
//         #else
//             std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
//         #endif
//     }

//     // generate and send bloom filter
//     if(pp.filter_type == "bloom"){

//         BloomFilter filter(vec_Fk2k1_Y.size(), pp.statistical_security_parameter);

//         filter.Insert(vec_Fk2k1_Y);

//         size_t filter_size = filter.ObjectSize(); 
//         io.SendInteger(filter_size);

//         char *buffer = new char[filter_size]; 
//         filter.WriteObject(buffer);
//         io.SendBytes(buffer, filter_size); 
//         std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> BloomFilter(F_k2k1(y_i)) ===> Server";
//         std::cout << " [" << (double)filter_size/(1024*1024) << " MB]" << std::endl;

//         delete[] buffer; 
//     } 
    
//     auto end_time = std::chrono::steady_clock::now(); 
//     auto running_time = end_time - start_time;
//     std::cout << "cwPRF-mqRPMT: Client side takes time = " 
//               << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

        
//     PrintSplitLine('-'); 
// }


}
#endif
