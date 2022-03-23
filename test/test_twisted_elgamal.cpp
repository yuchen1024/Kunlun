//#define DEBUG
#include "../pke/twisted_elgamal.hpp"
#include "../utility/print.hpp"


void benchmark_twisted_elgamal(size_t MSG_LEN, size_t TRADEOFF_NUM, size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the benchmark test >>>"<< std::endl;
    PrintSplitLine('-'); 
    std::cout << "MSG_LEN = " << MSG_LEN << std::endl;
    std::cout << "TRADEOFF_NUM = " << TRADEOFF_NUM << std::endl; 
    std::cout << "TEST_NUM = " << TEST_NUM << std::endl;
    PrintSplitLine('-'); 

    TwistedElGamal::PP pp = TwistedElGamal::Setup(MSG_LEN, TRADEOFF_NUM);
    TwistedElGamal::Initialize(pp); 
    PrintSplitLine('-'); 

    ECPoint pk[TEST_NUM];                      // pk
    BigInt sk[TEST_NUM];                       // sk
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
        std::tie(pk[i], sk[i]) = TwistedElGamal::KeyGen(pp); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test encryption efficiency */ 
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        CT[i] = TwistedElGamal::Enc(pp, pk[i], m[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test re-encryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        CT_new[i] = TwistedElGamal::ReEnc(pp, pk[i], sk[i], CT[i], r_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average re-encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test decryption efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        m_prime[i] = TwistedElGamal::Dec(pp, sk[i], CT_new[i]); 
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
        CT_result[i] = TwistedElGamal::HomoAdd(CT[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test homomorphic subtract efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        CT_result[i] = TwistedElGamal::HomoSub(CT[i], CT_new[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic sub takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    /* test scalar efficiency */
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        CT_result[i] = TwistedElGamal::ScalarMul(CT[i], k[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average scalar operation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
}



int main()
{  
    Global_Setup();
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  
    
    std::ios::sync_with_stdio(false);

    PrintSplitLine('-'); 
    std::cout << "Twisted ElGamal PKE test begins >>>>>>" << std::endl; 


    size_t MSG_LEN = 32; 
    size_t TRADEOFF_NUM = 7; 
    size_t TEST_NUM = 10000;

    benchmark_twisted_elgamal(MSG_LEN, TRADEOFF_NUM, TEST_NUM);

    
    PrintSplitLine('-'); 
    std::cout << "Twisted ElGamal PKE test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 

    ECGroup_Finalize(); 
    Context_Finalize(); 
    return 0; 
}


