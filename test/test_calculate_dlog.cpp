//#define DEBUG
#include "../pke/calculate_dlog.hpp"
#include "../common/print.hpp"


void benchmark_dlog(size_t RANGE_LEN, size_t TRADEOFF_NUM, size_t THREAD_NUM, size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "dlog benchmark test begins >>>"<< std::endl;
    PrintSplitLine('-'); 
    std::cout << "RANGE_LEN = " << RANGE_LEN << std::endl;
    std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 
    std::cout << "THREAD_NUM = " << THREAD_NUM << std::endl; 
    std::cout << "TEST_NUM = " << TEST_NUM << std::endl;
    PrintSplitLine('-'); 

    CheckDlogParameters(RANGE_LEN, TRADEOFF_NUM, THREAD_NUM); 

    ECPoint g = ECPoint(generator); 
    std::string keytable_filename = GetKeyTableFileName(g, RANGE_LEN, TRADEOFF_NUM);     
    /* generate babystep table */
    if(FileExist(keytable_filename) == false){
        if(THREAD_NUM > 1){
            ParallelBuildSerializeKeyTable(g, RANGE_LEN, TRADEOFF_NUM, THREAD_NUM, keytable_filename);
        }
        if(THREAD_NUM == 1){
            BuildSerializeKeyTable(g, RANGE_LEN, TRADEOFF_NUM, keytable_filename);
        }
    }
    
    // load the table from file 
    DeserializeKeyTableBuildHashMap(keytable_filename, RANGE_LEN, TRADEOFF_NUM); 

    BigInt x[TEST_NUM];                        // scalars  
    BigInt x_prime[TEST_NUM];                  // dlog scalars
    ECPoint Y[TEST_NUM];  
    BigInt MAX = BigInt(bn_2); 
    MAX = MAX.Exp(RANGE_LEN);
    for(auto i = 0; i < TEST_NUM; i++)
    {
        x[i] = GenRandomBigIntLessThan(MAX); 
        Y[i] = g * x[i];  
    }

    /* test dlog efficiency */ 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ParallelShanksDLOG(g, Y[i], RANGE_LEN, TRADEOFF_NUM, THREAD_NUM, x_prime[i]); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average dlog takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(x[i] != x_prime[i]){ 
            std::cout << "dlog fails at test case " << i << std::endl;
        } 
    }

    PrintSplitLine('-'); 
    std::cout << "dlog benchmark test finishes <<<" << std::endl; 
    PrintSplitLine('-'); 
}



int main()
{  
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  
    
    std::ios::sync_with_stdio(false);

    size_t RANGE_LEN = 46; 
    size_t TRADEOFF_NUM = 4; 
    size_t THREAD_NUM = 8; 
    size_t TEST_NUM = 128;  

    benchmark_dlog(RANGE_LEN, TRADEOFF_NUM, THREAD_NUM, TEST_NUM);
    


    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}
