//#define DEBUG
#include "../crypto/ec_point.hpp"
#include "../common/print.hpp"

void benchmark_ecc(size_t TEST_NUM)
{
    Print_SplitLine('-'); 
    std::cout << "ECC benchmark test begins >>>>>>" << std::endl; 
    Print_SplitLine('-'); 



    ECPoint A[TEST_NUM];                 // decrypted messages
    BigInt k[TEST_NUM];                  // scalars

    ECPoint g = ECPoint(generator); 
    ECPoint pk = GenRandomGenerator(); 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        k[i] = GenRandomBigIntLessThan(order); 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        //A[i] = g * k[i]; 
        EC_POINT_mul(group, A[i].point_ptr, k[i].bn_ptr, nullptr, nullptr, bn_ctx);
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "fixed point with precomputation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        A[i] = pk * k[i]; 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "fixed point without precomputation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    Print_SplitLine('-'); 
    std::cout << "ECC benchmark test finishes <<<<<<" << std::endl; 
    Print_SplitLine('-'); 
}



int main()
{  
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  

    size_t TEST_NUM = 10000;  

    benchmark_ecc(TEST_NUM); 
    

    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}



