#ifndef KUNLUN_CWPRF_MQRPMT_HPP_
#define KUNLUN_CWPRF_MQRPMT_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../crypto/prg.hpp"
#include "../../crypto/block.hpp"
#include "../../netio/stream_channel.hpp"
#include "../../filter/bloom_filter.hpp"



/*
** implement multi-query RPMT based on weak commutative PSU
** cuckoo filter is not gurantteed to be safe here, cause the filter may reveal the order of X
*/

namespace cwPRFmqRPMT{

struct PP
{
    bool malicious = false;
    std::string filter_type; // shuffle, bloom
    size_t statistical_security_parameter; // default=40 
};

// seriazlize
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.statistical_security_parameter; 
    fout << pp.filter_type;
    return fout; 
}

// load pp from file
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
    fin >> pp.statistical_security_parameter; 
    fin >> pp.filter_type;
    return fin; 
}

PP Setup(std::string filter_type, size_t lambda)
{
    PP pp; 
    pp.statistical_security_parameter = lambda; 
    pp.filter_type = filter_type; 
    return pp; 
}

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

std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN)
{
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 
    
    BigInt k1 = GenRandomBigIntLessThan(order); // pick a key k1

    std::vector <ECPoint> vec_Fk1_Y(LEN);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        vec_Fk1_Y[i] = Hash::BlockToECPoint(vec_Y[i]) * k1; // H(x_i)^k1
    }

    io.SendECPoints(vec_Fk1_Y.data(), LEN); 
    
    std::cout <<"cwPRF-based mqRPMT [step 1]: Server ===> F_k1(y_i) ===> Client";
    #ifdef POINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    std::vector<ECPoint> vec_Fk2_X(LEN); 
    io.ReceiveECPoints(vec_Fk2_X.data(), LEN);

    std::vector<ECPoint> vec_Fk1k2_X(LEN); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){ 
        vec_Fk1k2_X[i] = vec_Fk2_X[i] * k1; 
    }

    // compute the indication bit vector
    std::vector<uint8_t> vec_indication_bit(LEN);

    if(pp.filter_type == "shuffle"){
        std::vector<ECPoint> vec_Fk2k1_Y(LEN);
        io.ReceiveECPoints(vec_Fk2k1_Y.data(), LEN);
        std::unordered_set<ECPoint, ECPointHash> S;
        for(auto i = 0; i < LEN; i++){
            S.insert(vec_Fk2k1_Y[i]); 
        }
        for(auto i = 0; i < LEN; i++){
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

void Client(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{    
    PrintSplitLine('-'); 

    auto start_time = std::chrono::steady_clock::now(); 

    BigInt k2 = GenRandomBigIntLessThan(order); // pick a key

    std::vector<ECPoint> vec_Fk2_X(LEN); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        vec_Fk2_X[i] = Hash::BlockToECPoint(vec_X[i]) * k2; // H(x_i)^k2
    } 

    // first receive incoming data
    std::vector<ECPoint> vec_Fk1_Y(LEN);
    io.ReceiveECPoints(vec_Fk1_Y.data(), LEN); // receive Fk1_Y from Server

    // then send
    io.SendECPoints(vec_Fk2_X.data(), LEN);

    std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> F_k2(x_i) ===> Server"; 
    #ifdef POINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    std::vector<ECPoint> vec_Fk2k1_Y(LEN);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        vec_Fk2k1_Y[i] = vec_Fk1_Y[i] * k2; 
    }

    // permutation
    if(pp.filter_type == "shuffle"){
        std::random_shuffle(vec_Fk2k1_Y.begin(), vec_Fk2k1_Y.end());
        io.SendECPoints(vec_Fk2k1_Y.data(), LEN); 
        std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> Permutation(F_k2k1(y_i)) ===> Server"; 
        #ifdef POINT_COMPRESSED
            std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
        #else
            std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
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

}
#endif
