//#define DEBUG
#include "../crypto/setup.hpp"
#include "../pke/twisted_exponential_elgamal.hpp"

void benchmark_test(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the benchmark test >>>"<< std::endl;
    PrintSplitLine('-'); 
    std::cout << "MSG_LEN = " << MSG_LEN << std::endl;
    std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 
    std::cout << "TEST_NUM = " << TEST_NUM << std::endl;
    PrintSplitLine('-'); 

    TwistedExponentialElGamal::PP pp = TwistedExponentialElGamal::Setup(MSG_LEN, TRADEOFF_NUM);
    TwistedExponentialElGamal::Initialize(pp); 
    PrintSplitLine('-'); 

    ECPoint pk[TEST_NUM];                      // pk
    BigInt sk[TEST_NUM];                       // sk
    BigInt m[TEST_NUM];                        // messages  
    BigInt m_real[TEST_NUM];                  // decrypted messages
    BigInt k[TEST_NUM];                        // scalars
    TwistedExponentialElGamal::CT ct[TEST_NUM];            // CTs    
    TwistedExponentialElGamal::CT ct_new[TEST_NUM];        // re-randomized CTs
    TwistedExponentialElGamal::CT ct_result[TEST_NUM];     // homomorphic operation results
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
        std::tie(pk[i], sk[i]) = TwistedExponentialElGamal::KeyGen(pp); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct[i] = TwistedExponentialElGamal::Enc(pp, pk[i], m[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test re-encryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct_new[i] = TwistedExponentialElGamal::ReEnc(pp, pk[i], sk[i], ct[i], r_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average re-encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        m_real[i] = TwistedExponentialElGamal::Dec(pp, sk[i], ct_new[i]); 
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

    /* test homomorphic add efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct_result[i] = TwistedExponentialElGamal::HomoAdd(ct[i], ct_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test homomorphic subtract efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct_result[i] = TwistedExponentialElGamal::HomoSub(ct[i], ct_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic sub takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test scalar efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        ct_result[i] = TwistedExponentialElGamal::ScalarMul(ct[i], k[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average scalar operation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
}

void function_test(size_t MSG_LEN, size_t TRADEOFF_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the functionality test >>>"<< std::endl;
    PrintSplitLine('-'); 

    std::cout << "MSG_LEN = " << MSG_LEN << std::endl;
    std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 

    PrintSplitLine('-'); 

    TwistedExponentialElGamal::PP pp = TwistedExponentialElGamal::Setup(MSG_LEN, TRADEOFF_NUM);
    TwistedExponentialElGamal::Initialize(pp); 
    PrintSplitLine('-'); 

    ECPoint pk;                      // pk
    BigInt sk;                       // sk
    BigInt m_random, m_left, m_right;                       // messages  
    BigInt m_real;                  // decrypted messages
    TwistedExponentialElGamal::CT ct;            // CTs    


    m_random = GenRandomBigIntLessThan(pp.MSG_SIZE); 
    m_left = bn_0; 
    m_right = pp.MSG_SIZE - bn_1; 

    /* test keygen efficiency */ 
    std::tie(pk, sk) = TwistedExponentialElGamal::KeyGen(pp); 

    ct = TwistedExponentialElGamal::Enc(pp, pk, m_random);

    m_real = TwistedExponentialElGamal::Dec(pp, sk, ct); 
    if(m_random != m_real){ 
        std::cout << "decryption fails for random message" << std::endl;
    }
    else{
        std::cout << "decryption succeeds for random message" << std::endl;
    }

    ct = TwistedExponentialElGamal::Enc(pp, pk, m_left);

    m_real = TwistedExponentialElGamal::Dec(pp, sk, ct); 

    if(m_left != m_real){ 
        std::cout << "decryption fails for left boundary" << std::endl;
    }
    else{
        std::cout << "decryption succeeds for left boundary" << std::endl;
    }

    ct = TwistedExponentialElGamal::Enc(pp, pk, m_right);
    m_real = TwistedExponentialElGamal::Dec(pp, sk, ct); 
    if(m_right != m_real){ 
        std::cout << "decryption fails for right boundary" << std::endl;
    }
    else{
        std::cout << "decryption succeeds for right boundary" << std::endl;
    }

}


int main()
{  
    CRYPTO_Initialize(); 
    
    std::ios::sync_with_stdio(false);

    PrintSplitLine('-'); 
    std::cout << "Twisted Exponential ElGamal PKE test begins >>>>>>" << std::endl; 


    size_t MSG_LEN = 32; 
    size_t TRADEOFF_NUM = 7; 
    size_t TEST_NUM = 10000;

    function_test(MSG_LEN, TRADEOFF_NUM);
    benchmark_test(MSG_LEN, TRADEOFF_NUM, TEST_NUM);

    
    PrintSplitLine('-'); 
    std::cout << "Twisted Exponential ElGamal PKE test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 

    CRYPTO_Finalize(); 
    
    return 0; 
}


