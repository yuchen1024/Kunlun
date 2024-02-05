#ifndef KUNLUN_DDH_OPRF_HPP_
#define KUNLUN_DDH_OPRF_HPP_

/*
** implement (permuted)-OPRF based on the DDH Assumption
*/

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../netio/stream_channel.hpp"

namespace DDHOPRF{


/*
** the default domain element type is block, thus the default DOMAIN_SIZE is 16 bytes
** one can handle any domain element using a CRHF to fulfill domain extension
*/
struct PP
{
    size_t KEY_SIZE;   // the length of PRF key
    size_t RANGE_SIZE; // the length of PRF value
};

// seriazlize
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{ 
    fout << pp.KEY_SIZE;
    fout << pp.RANGE_SIZE;
    return fout; 
}

// load pp from file
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
    fin >> pp.KEY_SIZE;
    fin >> pp.RANGE_SIZE;
    return fin; 
}

PP Setup()
{
    PP pp; 
    pp.KEY_SIZE = BN_BYTE_LEN;
    pp.RANGE_SIZE = HASH_OUTPUT_LEN; 
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

/*
** pp: public parameters
** INPUT_NUM: the number of inputs
** permutation map: 0 <= permutation_map[i] < INPUT_NUM
** the default permutation_map should be an identity mapping
** return a random field element in Z_p as key
*/
std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<uint64_t> permutation_map, size_t INPUT_NUM)
{
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 

    BigInt k = GenRandomBigIntLessThan(order); // pick a key k

    std::vector<ECPoint> vec_mask_X(INPUT_NUM); 
    io.ReceiveECPoints(vec_mask_X.data(), INPUT_NUM);

    std::vector<ECPoint> vec_Fk_mask_X(INPUT_NUM); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < INPUT_NUM; i++){ 
        vec_Fk_mask_X[permutation_map[i]] = vec_mask_X[i] * k; 
    }

    io.SendECPoints(vec_Fk_mask_X.data(), INPUT_NUM);

    std::cout <<"DDH-based (permuted)-OPRF [step 2]: Server ===> F_k(mask_x_i) ===> Client";
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*INPUT_NUM/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*INPUT_NUM/(1024*1024) << " MB]" << std::endl;
    #endif


    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "DDH-based (permuted)-OPRF: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    PrintSplitLine('-'); 

    return k.ToByteVector(BN_BYTE_LEN); 
}

std::vector<std::vector<uint8_t>> Evaluate(PP &pp, std::vector<uint8_t> &key, std::vector<block> &vec_X, size_t INPUT_NUM)
{
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 

    BigInt k; 
    k.FromByteVector(key); 
    std::vector<ECPoint> vec_Fk_X(INPUT_NUM);
    std::vector<std::vector<uint8_t>> vec_PRF_value(INPUT_NUM, std::vector<uint8_t> (HASH_OUTPUT_LEN, 0)); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < INPUT_NUM; i++){ 
        vec_Fk_X[i] = Hash::BlockToECPoint(vec_X[i]) * k;
        vec_PRF_value[i] = Hash::ECPointToBytes(vec_Fk_X[i]); 
    }

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "DDH-based OPRF: Server side evaluation takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;        
    PrintSplitLine('-'); 

    return vec_PRF_value; 
}

std::vector<std::vector<uint8_t>> Client(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t INPUT_NUM) 
{    
    PrintSplitLine('-'); 

    auto start_time = std::chrono::steady_clock::now(); 

    BigInt r = GenRandomBigIntLessThan(order); // pick a mask

    std::vector<ECPoint> vec_mask_X(INPUT_NUM); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < INPUT_NUM; i++){
        vec_mask_X[i] = Hash::BlockToECPoint(vec_X[i]) * r; // H(x_i)^r
    } 
    io.SendECPoints(vec_mask_X.data(), INPUT_NUM);
    
    std::cout <<"DDH-based (permuted)-OPRF [step 1]: Client ===> mask_x_i ===> Server"; 
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*INPUT_NUM/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*INPUT_NUM/(1024*1024) << " MB]" << std::endl;
    #endif

    // first receive incoming data
    std::vector<ECPoint> vec_Fk_mask_X(INPUT_NUM);
    io.ReceiveECPoints(vec_Fk_mask_X.data(), INPUT_NUM); // receive F_k(mask_x_i) from Server

    BigInt r_inverse = r.ModInverse(order); 
    std::vector<ECPoint> vec_Fk_X(INPUT_NUM);
    std::vector<std::vector<uint8_t>> vec_PRF_value(INPUT_NUM, std::vector<uint8_t> (HASH_OUTPUT_LEN, 0)); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < INPUT_NUM; i++){
        vec_Fk_X[i] = vec_Fk_mask_X[i] * r_inverse; 
        vec_PRF_value[i] = Hash::ECPointToBytes(vec_Fk_X[i]); 
    }

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "DDH-based (permuted)-OPRF: Client side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;        
    PrintSplitLine('-'); 

    return vec_PRF_value; 

}

}
#endif
