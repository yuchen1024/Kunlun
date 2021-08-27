//#define DEBUG
#include "../twisted_elgamal_pke/twisted_elgamal_pke.hpp"
#include "../common/print.hpp"


void benchmark_twisted_elgamal(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t THREAD_NUM, size_t TEST_NUM)
{
    Print_SplitLine('-'); 
    std::cout << "begin the benchmark test (single thread), test_num = " << TEST_NUM << std::endl;

    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_Setup(pp, MSG_LEN, TRADEOFF_NUM, THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair[TEST_NUM];       // keypairs
    BigInt m[TEST_NUM];                        // messages  
    BigInt m_prime[TEST_NUM];                  // decrypted messages
    BigInt k[TEST_NUM];                        // scalars
    Twisted_ElGamal_CT CT[TEST_NUM];            // CTs    
    Twisted_ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
    Twisted_ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
    BigInt r_new[TEST_NUM];                  // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        m[i] = GenRandomBnLessThan(pp.MSG_SIZE); 
        k[i] = GenRandomBnLessThan(order); 
        r_new[i] = GenRandomBnLessThan(order); 
    }

    /* test keygen efficiency */ 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_KeyGen(pp, keypair[i]); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test re-encryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_ReEnc(pp, keypair[i].pk, keypair[i].sk, CT[i], r_new[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average re-encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]); 
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
        Twisted_ElGamal_HomoAdd(CT[i], CT_new[i], CT_result[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test homomorphic subtract efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_HomoSub(CT[i], CT_new[i], CT_result[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic sub takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test scalar efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_ScalarMul(CT[i], k[i], CT_result[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average scalar operation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
}


void benchmark_parallel_twisted_elgamal(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t THREAD_NUM, size_t TEST_NUM)
{
    std::cout << "begin the parallel benchmark test >>> " << std::endl; 
    
    std::cout << "MSG_LEN = " << MSG_LEN << std::endl;
    std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 
    std::cout << "THREAD_NUM = " << THREAD_NUM << std::endl; 
    std::cout << "TEST_NUM = " << TEST_NUM << std::endl;
    Print_SplitLine('-'); 

    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_Setup(pp, MSG_LEN, TRADEOFF_NUM, THREAD_NUM);

    Twisted_ElGamal_Initialize(pp); 
  

    Print_SplitLine('-'); 

    Twisted_ElGamal_KP keypair[TEST_NUM];       // keypairs
    BigInt m[TEST_NUM];                        // messages  
    BigInt m_prime[TEST_NUM];                  // decrypted messages
    BigInt k[TEST_NUM];                        // scalars
    Twisted_ElGamal_CT CT[TEST_NUM];            // CTs    
    Twisted_ElGamal_CT CT_new[TEST_NUM];        // re-randomized CTs
    Twisted_ElGamal_CT CT_result[TEST_NUM];     // homomorphic operation results
    BigInt r_new[TEST_NUM];                  // re-randomized randomness 

    for(auto i = 0; i < TEST_NUM; i++)
    {
        m[i] = GenRandomBnLessThan(pp.MSG_SIZE); 
        k[i] = GenRandomBnLessThan(order); 
        r_new[i] = GenRandomBnLessThan(order); 
    }

    /* test keygen efficiency */ 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_KeyGen(pp, keypair[i]); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_Enc(pp, keypair[i].pk, m[i], CT[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average parallel encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test re-encryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_ReEnc(pp, keypair[i].pk, keypair[i].sk, CT[i], r_new[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average parallel re-encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_Dec(pp, keypair[i].sk, CT_new[i], m_prime[i]);  
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average parallel decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(m[i] != m_prime[i]){ 
            std::cout << "decryption fails in the specified range in round " << i << std::endl;
        } 
    }

    /* test homomorphic add efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_HomoAdd(CT[i], CT_new[i], CT_result[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average parallel homomorphic add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test homomorphic subtract efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_HomoSub(CT[i], CT_new[i], CT_result[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average parallel homomorphic sub takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test scalar efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Twisted_ElGamal_Parallel_ScalarMul(CT[i], k[i], CT_result[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average parallel scalar operation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
}


int main()
{  
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);    

    // std::cout << sizeof(size_t) << std::endl;  
    // ECPoint A(generator);
    // size_t max_tablesize = size_t(pow(2, 32));
    // FindUniqueHash(A, max_tablesize); 

    Print_SplitLine('-'); 
    std::cout << "Twisted ElGamal PKE test begins >>>>>>" << std::endl; 
    Print_SplitLine('-'); 


    size_t MSG_LEN = 32; 
    size_t TRADEOFF_NUM = 7; 
    size_t THREAD_NUM = 8; 
    size_t TEST_NUM = 10000;  


    // test_twisted_elgamal(MSG_LEN, TRADEOFF_NUM, THREAD_NUM);
    // benchmark_twisted_elgamal(MSG_LEN, TRADEOFF_NUM, THREAD_NUM, TEST_NUM); 
    benchmark_parallel_twisted_elgamal(MSG_LEN, TRADEOFF_NUM, THREAD_NUM, TEST_NUM); 
    
    Print_SplitLine('-'); 
    std::cout << "Twisted ElGamal PKE test finishes <<<<<<" << std::endl; 
    Print_SplitLine('-'); 

    //test_twisted_elgamal_encaps(MSG_LEN, MAP_TUNNING, IO_THREAD_NUM, DEC_THREAD_NUM, TEST_NUM); 

    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}



