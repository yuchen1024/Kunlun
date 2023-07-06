//#define DEBUG
#include "../crypto/ec_point.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/hash.hpp"
#include "../utility/print.hpp"
#include "../crypto/setup.hpp"


void benchmark_ecc(size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "ECC benchmark test begins >>>>>>" << std::endl; 
    PrintSplitLine('-'); 

    ECPoint A[TEST_NUM];                 // decrypted messages
    ECPoint B[TEST_NUM]; 
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
        A[i] = g * k[i]; 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "fixed point mul with precomputation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        B[i] = pk * k[i];
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "fixed point mul without precomputation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        A[i] = A[i] + B[i];
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "point add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    PrintSplitLine('-'); 
    std::cout << "ECC benchmark test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 
}

void test_hash_to_point(size_t LEN)
{
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    std::vector<block> vec_M = PRG::GenRandomBlocks(seed, LEN);
    

    auto start_time = std::chrono::steady_clock::now(); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < LEN; i++){
        Hash::BlockToECPoint(vec_M[i]); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "hash to point takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

// void test_fast_hash_to_point(size_t LEN)
// {
//     PRG::Seed seed; 
//     PRG::SetSeed(seed, fix_key, 0); // initialize PRG
//     std::vector<block> vec_M = PRG::GenRandomBlocks(seed, LEN);
    

//     auto start_time = std::chrono::steady_clock::now(); 
//     #ifdef THREAD_SAFE
//     #pragma omp parallel for
//     #endif
//     for(auto i = 0; i < LEN; i++){
//         Hash::BlockToECPoint(vec_M[i]); 
//     }
//     auto end_time = std::chrono::steady_clock::now(); 
//     auto running_time = end_time - start_time;
//     std::cout << "hash to point takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
// }

// void test_ECPointToIndex(size_t LEN)
// {
//     std::vector<ECPoint> vec_A = GenRandomECPointVector(LEN); 
//     auto start_time = std::chrono::steady_clock::now(); 
//     #pragma omp parallel for
//     for(auto i = 0; i < LEN; i++){
//         //Hash::AdHocECPointToIndex(vec_A[i]);
//         Hash::SimpleECPointToIndex(vec_A[i]);  
//     }
//     auto end_time = std::chrono::steady_clock::now(); 
//     auto running_time = end_time - start_time;
//     std::cout << "hash to point takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
// }

// void test_matrix_transpose()
// {
//     size_t ROW_NUM = 1024*1024; 
//     size_t COLUMN_NUM = 128;

//     PRG::Seed seed; 
//     PRG::SetSeed(seed, nullptr, 0); 
//     std::vector<uint8_t> T1 = PRG::GenRandomBitMatrix(seed, ROW_NUM, COLUMN_NUM); 
//     //PrintBitMatrix(T1.data(), ROW_NUM, COLUMN_NUM);  

//     std::vector<uint8_t> T2(ROW_NUM/8 * COLUMN_NUM); 
//     // SSE_BitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());
//     BitMatrixTranspose(T1.data(), ROW_NUM, COLUMN_NUM, T2.data());
//     //PrintBitMatrix(T2.data(), COLUMN_NUM, ROW_NUM); 

//     std::vector<uint8_t> T3(ROW_NUM/8 * COLUMN_NUM); 
//     // SSE_BitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());
//     BitMatrixTranspose(T2.data(), COLUMN_NUM, ROW_NUM, T3.data());
//     //PrintBitMatrix(T3.data(), ROW_NUM, COLUMN_NUM);

//     CompareMatrix(T1.data(), T3.data(), ROW_NUM, COLUMN_NUM); 
// }


// void CompareMatrix(uint8_t *M1, uint8_t *M2, size_t ROW_NUM, size_t COLUMN_NUM)
// {
//     bool EQUAL = true; 
//     for(auto i = 0; i < ROW_NUM/8 * COLUMN_NUM; i++){
//         if(M1[i]!=M2[i]){
//             std::cout << i << std::endl;
//             EQUAL = false; 
//             break;
//         }
//     }
//     if (EQUAL) std::cout << "the two matrix are equal" << std::endl;
//     else std::cout << "the two matrix are not equal" << std::endl;
// }


int main()
{  
    CRYPTO_Initialize(); 

    //size_t TEST_NUM = 10000;  

    //benchmark_ecc(TEST_NUM); 

    // test_hash_to_point(TEST_NUM);


    // std::string test_filename = "testio.txt";
    // std::ofstream fout; 
    // fout.open(test_filename, std::ios::binary); 
    // if(!fout)
    // {
    //     std::cerr << test_filename << " open error" << std::endl;
    //     exit(1); 
    // }
    // std::string okvs_type = "GarbledCuckooTable";
    // fout << okvs_type << std::endl;
    // fout << "COMPRESSED" << std::endl;
    // fout.close();
    
    // std::ifstream fin; 
    // fin.open(test_filename, std::ios::binary); 
    // if(!fin)
    // {
    //     std::cerr << test_filename << " open error" << std::endl;
    //     exit(1); 
    // }
    // std::string res_type;
    // fin >> res_type;
    // std::string point_conversion_form;
    // fin >> point_conversion_form;
    // fin.close(); 

    // std::cout << res_type << std::endl; 
    // std::cout << point_conversion_form << std::endl; 

    // block a = Block::zero_block; 
    // Block::PrintBlock(a); 
    // Block::SetBitN(a, 63); 
    // Block::PrintBlock(a); 

    // Block::Calc2ToTheN(23);

    std::vector<BigInt> a(4096);
    #pragma omp parallel for
    for (int i = 0; i < 4096; i++){
        a[i] = i; 
        a[i] = a[i]+a[i]; 
    }
    std::cout << "ok" << std::endl;

    CRYPTO_Finalize(); 
    return 0; 
}



