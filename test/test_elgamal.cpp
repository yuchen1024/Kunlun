//#define DEBUG
#include "../crypto/setup.hpp"
#include "../pke/elgamal.hpp"

void benchmark_test(size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the benchmark test >>>"<< std::endl;
    PrintSplitLine('-'); 

#ifndef ENABLE_X25519_ACCELERATION
    ElGamal::PP pp = ElGamal::Setup();
    ECPoint pk[TEST_NUM];                      // pk
    BigInt sk[TEST_NUM];                       // sk
    ECPoint m[TEST_NUM];                        // messages  
    ECPoint m_real[TEST_NUM];                  // decrypted messages
    ElGamal::CT ct[TEST_NUM];            // ct
    ElGamal::CT ct_new[TEST_NUM];            // ct

    for(auto i = 0; i < TEST_NUM; i++)
    {
        m[i] = GenRandomECPoint();  
    }

    /* test keygen efficiency */ 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        std::tie(pk[i], sk[i]) = ElGamal::KeyGen(pp); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct[i] = ElGamal::Enc(pp, pk[i], m[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test re-encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct_new[i] = ElGamal::ReRand(pp, pk[i], ct[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average re-randomization takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        m_real[i] = ElGamal::Dec(pp, sk[i], ct_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(m[i] != m_real[i]){ 
            std::cout << "decryption fails in the specified range" << std::endl;
        } 
    }
#else
    ElGamal::PP pp = ElGamal::Setup();
    EC25519Point pk[TEST_NUM];                      // pk
    std::vector<std::vector<uint8_t>> sk(TEST_NUM, std::vector<uint8_t> (32, 0));                       // sk
    EC25519Point m[TEST_NUM];                        // messages  
    EC25519Point m_real[TEST_NUM];                  // decrypted messages
    ElGamal::CT ct[TEST_NUM];            // cts    

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    for(auto i = 0; i < TEST_NUM; i++)
    {
        GenRandomBytes(seed, m[i].px, 32);  
    }

    /* test keygen efficiency */ 
    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        std::tie(pk[i], sk[i]) = ElGamal::KeyGen(pp); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct[i] = ElGamal::Enc(pp, pk[i], m[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        m_real[i] = ElGamal::Dec(pp, sk[i], ct[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    for(auto i = 0; i < TEST_NUM; i++)
    {
        if(m[i] != m_real[i]){ 
            std::cout << "decryption fails in the specified range" << std::endl;
        } 
    }
#endif

}


void function_test()
{
    PrintSplitLine('-'); 
    std::cout << "begin the functionality test >>>"<< std::endl;
    PrintSplitLine('-'); 

#ifndef ENABLE_X25519_ACCELERATION
    ElGamal::PP pp = ElGamal::Setup();
    ECPoint pk;                      // pk
    BigInt sk;              // sk
    ECPoint m_random;     // message  
    ECPoint m_real;       // decrypted message
    ElGamal::CT ct;            // ct   
    ElGamal::CT ct_new;            // ct    

    /* test keygen efficiency */ 
    std::tie(pk, sk) = ElGamal::KeyGen(pp); 
    ct = ElGamal::Enc(pp, pk, m_random);
    ct_new = ElGamal::ReRand(pp, pk, ct); 
    m_real = ElGamal::Dec(pp, sk, ct); 
    if(m_random != m_real){ 
        std::cout << "decryption fails for random message" << std::endl;
    }
    else{
        std::cout << "decryption succeeds for random message" << std::endl;
    }
#else
    ElGamal::PP pp = ElGamal::Setup();
    EC25519Point pk;                      // pk
    std::vector<uint8_t> sk;              // sk
    EC25519Point m_random;     // message  
    EC25519Point m_real;       // decrypted message
    ElGamal::CT ct;            // ct    

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    GenRandomBytes(seed, m_random.px, 32);  // generate a random message

    /* test keygen efficiency */ 
    std::tie(pk, sk) = ElGamal::KeyGen(pp); 
    ct = ElGamal::Enc(pp, pk, m_random);
    m_real = ElGamal::Dec(pp, sk, ct); 
    if(m_random != m_real){ 
        std::cout << "decryption fails for random message" << std::endl;
    }
    else{
        std::cout << "decryption succeeds for random message" << std::endl;
    }
#endif
}


int main()
{  
    CRYPTO_Initialize();  
    
    std::ios::sync_with_stdio(false);

    PrintSplitLine('-'); 
    std::cout << "ElGamal PKE test begins >>>>>>" << std::endl; 
    PrintSplitLine('-'); 

    function_test(); 
        
    size_t TEST_NUM = 10000;
    benchmark_test(TEST_NUM);

    PrintSplitLine('-'); 
    std::cout << "ElGamal PKE test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 

    CRYPTO_Finalize(); 
    
    return 0; 
}


