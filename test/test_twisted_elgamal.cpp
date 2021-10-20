//#define DEBUG
#include "../pke/twisted_elgamal.hpp"
#include "../common/print.hpp"


void benchmark_twisted_elgamal(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t DEC_THREAD_NUM, size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the benchmark test >>>"<< std::endl;
    PrintSplitLine('-'); 
    std::cout << "MSG_LEN = " << MSG_LEN << std::endl;
    std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 
    std::cout << "DEC_THREAD_NUM = " << DEC_THREAD_NUM << std::endl; 
    std::cout << "TEST_NUM = " << TEST_NUM << std::endl;
    PrintSplitLine('-'); 

    TwistedElGamal::PP pp; 
    TwistedElGamal::Setup(pp, MSG_LEN, TRADEOFF_NUM, DEC_THREAD_NUM);
    TwistedElGamal::Initialize(pp); 
    PrintSplitLine('-'); 

    TwistedElGamal::KP keypair[TEST_NUM];       // keypairs
    BigInt m[TEST_NUM];                        // messages  
    BigInt m_prime[TEST_NUM];                  // decrypted messages
    BigInt k[TEST_NUM];                        // scalars
    TwistedElGamal::CT CT[TEST_NUM];            // CTs    
    TwistedElGamal::CT CT_new[TEST_NUM];        // re-randomized CTs
    TwistedElGamal::CT CT_result[TEST_NUM];     // homomorphic operation results
    BigInt r_new[TEST_NUM];                  // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        m[i] = GenRandomBigIntLessThan(pp.MSG_SIZE); 
        k[i] = GenRandomBigIntLessThan(order); 
        r_new[i] = GenRandomBigIntLessThan(order); 
    }

    /* test keygen efficiency */ 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::KeyGen(pp, keypair[i]); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test re-encryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::ReEnc(pp, keypair[i].pk, keypair[i].sk, CT[i], r_new[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average re-encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(m[i] != m_prime[i]){ 
            std::cout << "decryption fails in the specified range" << std::endl;
        } 
    }

    /* test homomorphic add efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::HomoAdd(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test homomorphic subtract efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::HomoSub(CT_result[i], CT[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic sub takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test scalar efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        TwistedElGamal::ScalarMul(CT_result[i], CT[i], k[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average scalar operation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
}



int main()
{  
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  
    
    std::ios::sync_with_stdio(false);

    PrintSplitLine('-'); 
    std::cout << "Twisted ElGamal PKE test begins >>>>>>" << std::endl; 


    size_t MSG_LEN = 40; 
    size_t TRADEOFF_NUM = 7; 
    size_t DEC_THREAD_NUM = 8; 
    size_t TEST_NUM = 10000;  

    benchmark_twisted_elgamal(MSG_LEN, TRADEOFF_NUM, DEC_THREAD_NUM, TEST_NUM);

    // THREAD_NUM = 8; 
    // benchmark_parallel_twisted_elgamal(MSG_LEN, TRADEOFF_NUM, THREAD_NUM, TEST_NUM); 
    
    PrintSplitLine('-'); 
    std::cout << "Twisted ElGamal PKE test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 

    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}


// void benchmark_parallel_twisted_elgamal(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t DEC_THREAD_NUM, size_t TEST_NUM)
// {
//     PrintSplitLine('-'); 
//     std::cout << "begin the parallel benchmark test >>> " << std::endl; 
//     Print_SplitLine('-'); 
//     std::cout << "MSG_LEN = " << MSG_LEN << std::endl;
//     std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 
//     std::cout << "DEC THREAD_NUM = " << DEC_THREAD_NUM << std::endl; 
//     std::cout << "TEST_NUM = " << TEST_NUM << std::endl;
//     Print_SplitLine('-'); 

//     Twisted_ElGamal_PP pp; 
//     Twisted_ElGamal_Setup(pp, MSG_LEN, TRADEOFF_NUM, THREAD_NUM);

//     Twisted_ElGamal_Initialize(pp); 
//     Print_SplitLine('-'); 

//     Twisted_ElGamal_KP keypair[TEST_NUM];       // keypairs
//     BigInt m[TEST_NUM];                        // messages  
//     BigInt m_prime[TEST_NUM];                  // decrypted messages
//     BigInt k[TEST_NUM];                        // scalars
//     Twisted_ElGamal_CT CT[TEST_NUM];            // CTs    
//     Twisted_ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
//     Twisted_ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
//     BigInt r_new[TEST_NUM];                  // re-randomized randomness 

//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         m[i] = GenRandomBigIntLessThan(pp.MSG_SIZE); 
//         k[i] = GenRandomBigIntLessThan(order); 
//         r_new[i] = GenRandomBigIntLessThan(order); 
//     }

//     /* test keygen efficiency */ 
//     auto start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_KeyGen(pp, keypair[i]); 
//     }
//     auto end_time = std::chrono::steady_clock::now(); 
//     auto running_time = end_time - start_time;
//     std::cout << "average key generation takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

//     /* test encryption efficiency */ 
//     start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_Parallel_Enc(pp, keypair[i].pk, m[i], CT[i]);
//     }
//     end_time = std::chrono::steady_clock::now(); 
//     running_time = end_time - start_time;
//     std::cout << "average parallel encryption takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

//     /* test re-encryption efficiency */
//     start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_Parallel_ReEnc(pp, keypair[i].pk, keypair[i].sk, CT[i], r_new[i], CT_new[i]); 
//     }
//     end_time = std::chrono::steady_clock::now(); 
//     running_time = end_time - start_time;
//     std::cout << "average parallel re-encryption takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

//     /* test decryption efficiency */
//     start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_Parallel_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]);  
//     }
//     end_time = std::chrono::steady_clock::now(); 
//     running_time = end_time - start_time;
//     std::cout << "average parallel decryption takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         if(m[i] != m_prime[i]){ 
//             std::cout << "decryption fails in the specified range in round " << i << std::endl;
//         } 
//     }

//     /* test homomorphic add efficiency */
//     start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_Parallel_HomoAdd(CT[i], CT_new[i], CT_result[i]); 
//     }
//     end_time = std::chrono::steady_clock::now(); 
//     running_time = end_time - start_time;
//     std::cout << "average parallel homomorphic add takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

//     /* test homomorphic subtract efficiency */
//     start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_Parallel_HomoSub(CT[i], CT_new[i], CT_result[i]); 
//     }
//     end_time = std::chrono::steady_clock::now(); 
//     running_time = end_time - start_time;
//     std::cout << "average parallel homomorphic sub takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

//     /* test scalar efficiency */
//     start_time = std::chrono::steady_clock::now(); 
//     for(auto i = 0; i < TEST_NUM; i++)
//     {
//         Twisted_ElGamal_Parallel_ScalarMul(CT_result[i], CT[i], k[i]); 
//     }
//     end_time = std::chrono::steady_clock::now(); 
//     running_time = end_time - start_time;
//     std::cout << "average parallel scalar operation takes time = " 
//     << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
// }

