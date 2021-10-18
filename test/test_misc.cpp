//#define DEBUG
#include "../crypto/ec_point.hpp"
#include "../common/print.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/hash.hpp"

void benchmark_ecc(size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "ECC benchmark test begins >>>>>>" << std::endl; 
    PrintSplitLine('-'); 



    ECPoint A[TEST_NUM];                 // decrypted messages
    BigInt k[TEST_NUM];                  // scalars

    ECPoint g = ECPoint(generator); 
    ECPoint pk = GenRandomGenerator(); 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        k[i] = GenRandomBigIntLessThan(order); 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    #ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
    for(auto i = 0; i < TEST_NUM; i++)
    {
        A[i] = g * k[i]; 
        //EC_POINT_mul(group, A[i].point_ptr, k[i].bn_ptr, nullptr, nullptr, bn_ctx);
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "fixed point with precomputation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    #ifdef THREAD_SAFE
        #pragma omp parallel for
    #endif
    for(auto i = 0; i < TEST_NUM; i++)
    {
        A[i] = pk * k[i];
        //A[i] = pk.ThreadSafeMul(k[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "fixed point without precomputation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    PrintSplitLine('-'); 
    std::cout << "ECC benchmark test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 
}

void test_hash_to_point(size_t LEN)
{
    PRG::Seed seed; 
    PRG::SetSeed(seed, fix_key, 0); // initialize PRG
    std::vector<block> vec_M = PRG::GenRandomBlocks(seed, LEN);
    

    auto start_time = std::chrono::steady_clock::now(); 
    //#pragma omp parallel for
    for(auto i = 0; i < LEN; i++){
        Hash::StringToECPoint(Block::ToString(vec_M[i])); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "hash to point takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

void test_fast_hash_to_point(size_t LEN)
{
    PRG::Seed seed; 
    PRG::SetSeed(seed, fix_key, 0); // initialize PRG
    std::vector<block> vec_M = PRG::GenRandomBlocks(seed, LEN);
    

    auto start_time = std::chrono::steady_clock::now(); 
    #ifdef THREAD_SAFE
    #pragma omp parallel for
    #endif
    for(auto i = 0; i < LEN; i++){
        Hash::BlockToECPoint(vec_M[i]); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "hash to point takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

int main()
{  
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  

    size_t TEST_NUM = 1024*32;  

    benchmark_ecc(TEST_NUM); 

    test_fast_hash_to_point(1024*1024); 
    

    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}



