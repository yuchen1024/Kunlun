//#define DEBUG
#include "../crypto/ec_point.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/hash.hpp"

#include "../utility/print.hpp"
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
    std::cout << "fixed point mul with precomputation takes time = " 
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
    std::cout << "fixed point mul without precomputation takes time = " 
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

// void test_endian()
// {
//     std::cout << sizeof(block) << std::endl; 
//     std::vector<uint8_t> A(16); 
//     A[0] = 0xFF;
//     A[1] = 0x0F; 
//     A[2] = 0xF0; 
//     A[3] = 0xDD; 
//     A[4] = 0xFF;
//     A[5] = 0x01; 
//     A[6] = 0x10; 
//     A[7] = 0x25; 
//     A[8] = 0x56;
//     A[9] = 0x34; 
//     A[10] = 0x67; 
//     A[11] = 0x98; 
//     A[12] = 0x22;
//     A[13] = 0x41; 
//     A[14] = 0x38; 
//     A[15] = 0x66; 

//     block B; 
//     memcpy(&B, A.data(), 16); 

//     //PrintBlock(B); 
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
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  

    size_t TEST_NUM = 1024*32;  

    benchmark_ecc(TEST_NUM); 

    test_fast_hash_to_point(1024*1024); 
    

    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}



