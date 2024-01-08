#ifndef KUNLUN_CWPRF_MQRPMT_HPP_
#define KUNLUN_CWPRF_MQRPMT_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../crypto/prg.hpp"
#include "../../crypto/block.hpp"
#include "../../netio/stream_channel.hpp"
#include "../../filter/bloom_filter.hpp"
#include "../../utility/serialization.hpp"

/*
** implement multi-query RPMT based on weak commutative PRF
** cuckoo filter is not gurantteed to be safe here, cause the filter may reveal the order of X
*/


#define BLOOMFILTER 

namespace cwPRFmqRPMT{
    
using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    size_t statistical_security_parameter; // default=40 
    size_t LOG_SERVER_LEN; 
    size_t SERVER_LEN; 
    size_t LOG_CLIENT_LEN; 
    size_t CLIENT_LEN; 
};

// serialize
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.statistical_security_parameter; 
    fout << pp.LOG_SERVER_LEN;
    fout << pp.SERVER_LEN; 
    fout << pp.LOG_CLIENT_LEN;
    fout << pp.CLIENT_LEN; 

    return fout; 
}

// load pp from file
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
    fin >> pp.statistical_security_parameter; 
    fin >> pp.LOG_SERVER_LEN;
    fin >> pp.SERVER_LEN;
    fin >> pp.LOG_CLIENT_LEN;
    fin >> pp.CLIENT_LEN;

    return fin; 
}

PP Setup(size_t statistical_security_parameter, size_t LOG_SERVER_LEN, size_t LOG_CLIENT_LEN)
{
    PP pp; 
    pp.statistical_security_parameter = statistical_security_parameter; 
    pp.LOG_SERVER_LEN = LOG_SERVER_LEN; 
    pp.SERVER_LEN = size_t(pow(2, pp.LOG_SERVER_LEN)); 
    pp.LOG_CLIENT_LEN = LOG_CLIENT_LEN; 
    pp.CLIENT_LEN = size_t(pow(2, pp.LOG_CLIENT_LEN)); 
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

#ifndef ENABLE_X25519_ACCELERATION
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
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        vec_Fk1_Y[i] = Hash::BlockToECPoint(vec_Y[i]) * k1; // H(y_i)^k1
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
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.CLIENT_LEN; i++){ 
        vec_Fk1k2_X[i] = vec_Fk2_X[i] * k1; 
    }

    // compute the indication bit vector
    std::vector<uint8_t> vec_indication_bit(pp.CLIENT_LEN);

    #ifdef BLOOMFILTER
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
    #else
        std::vector<ECPoint> vec_Fk2k1_Y(pp.SERVER_LEN);
        io.ReceiveECPoints(vec_Fk2k1_Y.data(), pp.SERVER_LEN);
        std::unordered_set<ECPoint, ECPointHash> S;
        for(auto i = 0; i < pp.SERVER_LEN; i++){
            S.insert(vec_Fk2k1_Y[i]); 
        }
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for(auto i = 0; i < pp.CLIENT_LEN; i++){
            if(S.find(vec_Fk1k2_X[i]) == S.end()) vec_indication_bit[i] = 0;  
            else vec_indication_bit[i] = 1;
        }
    #endif

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "cwPRF-based mqRPMT: Server side takes time = " 
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
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
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
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        vec_Fk2k1_Y[i] = vec_Fk1_Y[i] * k2; 
    }

    // generate and send bloom filter
    #ifdef BLOOMFILTER
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
    #else
        // permutation
        std::shuffle(vec_Fk2k1_Y.begin(), vec_Fk2k1_Y.end(), global_built_in_prg);
        io.SendECPoints(vec_Fk2k1_Y.data(), pp.SERVER_LEN); 
        std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> Permutation(F_k2k1(y_i)) ===> Server"; 
        #ifdef ECPOINT_COMPRESSED
            std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN * pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
        #else
            std::cout << " [" << (double)POINT_BYTE_LEN*pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
        #endif
    #endif
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "cwPRF-based mqRPMT: Client side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

        
    PrintSplitLine('-'); 
}

#else

std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<block> &vec_Y)
{
    if(pp.SERVER_LEN != vec_Y.size()){
        std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
        exit(1);  
    }

    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 

    std::vector<uint8_t> k1(32);
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    GenRandomBytes(seed, k1.data(), 32);  // pick a key k1

    std::vector<EC25519Point> vec_Hash_Y(pp.SERVER_LEN);
    std::vector<EC25519Point> vec_Fk1_Y(pp.SERVER_LEN);

    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        Hash::BlockToBytes(vec_Y[i], vec_Hash_Y[i].px, 32); 
        vec_Fk1_Y[i] = vec_Hash_Y[i] * k1; 
    }

    io.SendEC25519Points(vec_Fk1_Y.data(), pp.SERVER_LEN); 
    
    std::cout <<"cwPRF-based mqRPMT [step 1]: Server ===> F_k1(y_i) ===> Client";
    
    std::cout << " [" << 32*pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;

    std::vector<EC25519Point> vec_Fk2_X(pp.CLIENT_LEN); 
    io.ReceiveEC25519Points(vec_Fk2_X.data(), pp.CLIENT_LEN);

    std::vector<EC25519Point> vec_Fk1k2_X(pp.CLIENT_LEN); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.CLIENT_LEN; i++){ 
        vec_Fk1k2_X[i] = vec_Fk2_X[i] * k1; // (H(x_i)^k2)^k1
    }

    // compute the indication bit vector
    std::vector<uint8_t> vec_indication_bit(pp.CLIENT_LEN);

    #ifdef BLOOMFILTER
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
    #else
        std::vector<EC25519Point> vec_Fk2k1_Y(pp.SERVER_LEN);
        io.ReceiveEC25519Points(vec_Fk2k1_Y.data(), pp.SERVER_LEN);
        std::unordered_set<EC25519Point, EC25519PointHash> S;
        for(auto i = 0; i < pp.SERVER_LEN; i++){
            S.insert(vec_Fk2k1_Y[i]); 
        }
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for(auto i = 0; i < pp.CLIENT_LEN; i++){
            if(S.find(vec_Fk1k2_X[i]) == S.end()) vec_indication_bit[i] = 0;  
            else vec_indication_bit[i] = 1;
        }
    #endif

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
        std::cerr << "input size of vec_X does not match public parameters" << std::endl;
        exit(1);  
    }
    
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 

    std::vector<uint8_t> k2(32);
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    GenRandomBytes(seed, k2.data(), 32);  // pick a key k2

    std::vector<EC25519Point> vec_Hash_X(pp.CLIENT_LEN); 
    std::vector<EC25519Point> vec_Fk2_X(pp.CLIENT_LEN); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.CLIENT_LEN; i++){
        Hash::BlockToBytes(vec_X[i], vec_Hash_X[i].px, 32); 
        vec_Fk2_X[i] = vec_Hash_X[i] * k2; 
    } 

    // first receive incoming data
    std::vector<EC25519Point> vec_Fk1_Y(pp.SERVER_LEN);
    io.ReceiveEC25519Points(vec_Fk1_Y.data(), pp.SERVER_LEN); // receive Fk1_Y from Server

    // then send
    io.SendEC25519Points(vec_Fk2_X.data(), pp.CLIENT_LEN);

    std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> F_k2(x_i) ===> Server"; 

    std::cout << " [" << 32*pp.CLIENT_LEN/(1024*1024) << " MB]" << std::endl;


    std::vector<EC25519Point> vec_Fk2k1_Y(pp.SERVER_LEN);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        vec_Fk2k1_Y[i] = vec_Fk1_Y[i] * k2; // (H(y_i)^k1)^k2
    }


    #ifdef BLOOMFILTER
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
    #else
    // permutation
        std::shuffle(vec_Fk2k1_Y.begin(), vec_Fk2k1_Y.end(), global_built_in_prg);
        io.SendEC25519Points(vec_Fk2k1_Y.data(), pp.SERVER_LEN); 
        std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> Permutation(F_k2k1(y_i)) ===> Server"; 
        std::cout << " [" << (double)32 * pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "cwPRF-mqRPMT: Client side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
        
    PrintSplitLine('-'); 
}

#endif

}
#endif

// previous code using C interface of X25519: roughly 10% faster than current code using C++ interfaces  
// std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<block> &vec_Y)
// {
//     if(pp.SERVER_LEN != vec_Y.size()){
//         std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
//         exit(1);  
//     }

//     PrintSplitLine('-'); 
//     auto start_time = std::chrono::steady_clock::now(); 

//     uint8_t k1[32];
//     PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
//     GenRandomBytes(seed, k1, 32);  // pick a key k1

//     std::vector<EC25519Point> vec_Hash_Y(pp.SERVER_LEN);
//     std::vector<EC25519Point> vec_Fk1_Y(pp.SERVER_LEN);

//     #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
//     for(auto i = 0; i < pp.SERVER_LEN; i++){
//         Hash::BlockToBytes(vec_Y[i], vec_Hash_Y[i].px, 32); 
//         x25519_scalar_mulx(vec_Fk1_Y[i].px, k1, vec_Hash_Y[i].px); 
//     }

//     io.SendEC25519Points(vec_Fk1_Y.data(), pp.SERVER_LEN); 
    
//     std::cout <<"cwPRF-based mqRPMT [step 1]: Server ===> F_k1(y_i) ===> Client";
    
//     std::cout << " [" << 32*pp.SERVER_LEN/(1024*1024) << " MB]" << std::endl;

//     std::vector<EC25519Point> vec_Fk2_X(pp.CLIENT_LEN); 
//     io.ReceiveEC25519Points(vec_Fk2_X.data(), pp.CLIENT_LEN);

//     std::vector<EC25519Point> vec_Fk1k2_X(pp.CLIENT_LEN); 
//     #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
//     for(auto i = 0; i < pp.CLIENT_LEN; i++){ 
//         x25519_scalar_mulx(vec_Fk1k2_X[i].px, k1, vec_Fk2_X[i].px); // (H(x_i)^k2)^k1
//     }

//     // compute the indication bit vector
//     std::vector<uint8_t> vec_indication_bit(pp.CLIENT_LEN);

//     if(pp.filter_type == "shuffle"){
//         std::cerr << "does not support shuffle" << std::endl;
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

// void Client(NetIO &io, PP &pp, std::vector<block> &vec_X) 
// {    
//     if(pp.CLIENT_LEN != vec_X.size()){
//         std::cerr << "input size of vec_X does not match public parameters" << std::endl;
//         exit(1);  
//     }
    
//     PrintSplitLine('-'); 
//     auto start_time = std::chrono::steady_clock::now(); 

//     uint8_t k2[32];
//     PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
//     GenRandomBytes(seed, k2, 32);  // pick a key k2

//     std::vector<EC25519Point> vec_Hash_X(pp.CLIENT_LEN); 
//     std::vector<EC25519Point> vec_Fk2_X(pp.CLIENT_LEN); 
//     #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
//     for(auto i = 0; i < pp.CLIENT_LEN; i++){
//         Hash::BlockToBytes(vec_X[i], vec_Hash_X[i].px, 32); 
//         x25519_scalar_mulx(vec_Fk2_X[i].px, k2, vec_Hash_X[i].px); 
//     } 

//     // first receive incoming data
//     std::vector<EC25519Point> vec_Fk1_Y(pp.SERVER_LEN);
//     io.ReceiveEC25519Points(vec_Fk1_Y.data(), pp.SERVER_LEN); // receive Fk1_Y from Server

//     // then send
//     io.SendEC25519Points(vec_Fk2_X.data(), pp.CLIENT_LEN);

//     std::cout <<"cwPRF-based mqRPMT [step 2]: Client ===> F_k2(x_i) ===> Server"; 

//     std::cout << " [" << 32*pp.CLIENT_LEN/(1024*1024) << " MB]" << std::endl;


//     std::vector<EC25519Point> vec_Fk2k1_Y(pp.SERVER_LEN);
//     #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
//     for(auto i = 0; i < pp.SERVER_LEN; i++){
//         x25519_scalar_mulx(vec_Fk2k1_Y[i].px, k2, vec_Fk1_Y[i].px); // (H(x_i)^k2)^k1
//     }

//     // permutation
//     if(pp.filter_type == "shuffle"){
//         std::cerr << "does not support shuffle" << std::endl;
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
