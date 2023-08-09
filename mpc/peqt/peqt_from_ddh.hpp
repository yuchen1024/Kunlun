#ifndef KUNLUN_DDH_PEQT_HPP_
#define KUNLUN_DDH_PEQT_HPP_

#include "../../include/std.inc"
#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../netio/stream_channel.hpp"


/*
** implement DDH-based PEQT based on DDH-based OPRF
*/

namespace DDHPEQT{

using Serialization::operator<<; 
using Serialization::operator>>; 

std::vector<uint64_t> Send(NetIO &io, std::vector<block> &vec_Y, size_t ROW_NUM, size_t COLUMN_NUM)
{
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 
    
    size_t LEN = vec_Y.size(); 
    if(LEN != ROW_NUM*COLUMN_NUM){
        std::cerr << "size does not match" << std::endl; 
    }

    BigInt k = GenRandomBigIntLessThan(order); // pick a key k

    std::vector<uint64_t> row_map(ROW_NUM);
    for(auto i = 0; i < ROW_NUM; i++) row_map[i] = i; 
    std::shuffle(row_map.begin(), row_map.end(), global_built_in_prg); 

    std::vector<uint64_t> column_map(COLUMN_NUM); 
    for(auto j = 0; j < COLUMN_NUM; j++) column_map[j] = j; 
    std::shuffle(column_map.begin(), column_map.end(), global_built_in_prg);

    std::vector<uint64_t> permutation_map(LEN); 
    for(auto i = 0; i < ROW_NUM; i++){
        for(auto j = 0; j < COLUMN_NUM; j++){
            permutation_map[i*COLUMN_NUM+j] = row_map[i]*COLUMN_NUM + column_map[j]; 
        }
    }

    std::vector<ECPoint> vec_Fk_permuted_Y(LEN);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < LEN; i++){
        vec_Fk_permuted_Y[permutation_map[i]] = Hash::BlockToECPoint(vec_Y[i]) * k; 
    }
    
    std::vector<ECPoint> vec_mask_X(LEN); 
    io.ReceiveECPoints(vec_mask_X.data(), LEN);     
    
    io.SendECPoints(vec_Fk_permuted_Y.data(), LEN); 
    std::cout <<"DDH-based PEQT [step 2]: Sender ===> Permutation[F_k(y_i)] ===> Receiver";
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #endif


    std::vector<ECPoint> vec_Fk_permuted_mask_X(LEN);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < LEN; i++){
        vec_Fk_permuted_mask_X[permutation_map[i]] = vec_mask_X[i] * k; 
    }
    
    io.SendECPoints(vec_Fk_permuted_mask_X.data(), LEN); 
    std::cout <<"DDH-based PEQT [step 2]: Sender ===> Permutation[F_k(mask_x_i)] ===> Receiver";
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "DDH-based PEQT: Sender side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-'); 

    return permutation_map; 
}

std::vector<uint8_t> Receive(NetIO &io, std::vector<block> &vec_X, size_t ROW_NUM, size_t COLUMN_NUM) 
{    
    PrintSplitLine('-'); 
    
    size_t LEN = vec_X.size(); 
    if(LEN != ROW_NUM*COLUMN_NUM){
        std::cerr << "size does not match" << std::endl; 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    BigInt r = GenRandomBigIntLessThan(order); // pick a key

    std::vector<ECPoint> vec_mask_X(LEN); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < LEN; i++){
        vec_mask_X[i] = Hash::BlockToECPoint(vec_X[i]) * r; 
    } 

    io.SendECPoints(vec_mask_X.data(), LEN);

    std::cout <<"DDH-based PEQT [step 1]: Receiver ===> mask_x_i ===> Sender"; 
    #ifdef ECPOINT_COMPRESSED
        std::cout << " [" << (double)POINT_COMPRESSED_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #else
        std::cout << " [" << (double)POINT_BYTE_LEN*LEN/(1024*1024) << " MB]" << std::endl;
    #endif

    std::vector<ECPoint> vec_Fk_permuted_Y(LEN);
    io.ReceiveECPoints(vec_Fk_permuted_Y.data(), LEN); // receive Fk_permuted_Y from Sender

    std::vector<ECPoint> vec_Fk_permuted_mask_X(LEN);
    io.ReceiveECPoints(vec_Fk_permuted_mask_X.data(), LEN); // receive Fk_permuted_Y from Sender

    std::vector<uint8_t> vec_result(LEN);
    BigInt r_inverse = r.ModInverse(order); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < LEN; i++){
        vec_result[i] = vec_Fk_permuted_Y[i].CompareTo(vec_Fk_permuted_mask_X[i] * r_inverse); 
    }
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "DDH-based PEQT: Receiver side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-'); 

    return vec_result; 
}

}
#endif
