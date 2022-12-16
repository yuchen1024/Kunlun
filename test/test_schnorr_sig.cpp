//#define DEBUG
#include "../signature/schnorr.hpp"
#include "../utility/print.hpp"
#include "../crypto/setup.hpp"

void test_schnorr(size_t TEST_NUM)
{
    std::cout << "begin the basic correctness test >>>" << std::endl; 
    
    Schnorr::PP pp = Schnorr::Setup(); 
    std::vector<ECPoint> pk(TEST_NUM); 
    std::vector<BigInt> sk(TEST_NUM);

    auto start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        std::tie(pk[i], sk[i]) = Schnorr::KeyGen(pp); 
    }
    auto end_time = std::chrono::steady_clock::now(); 
    
    auto running_time = end_time - start_time;
    std::cout << "key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;

    std::vector<Schnorr::SIG> sigma(TEST_NUM); 
    
    std::string message = "crypto is hard";  

    start_time = std::chrono::steady_clock::now(); 
    
    for(auto i = 0; i < TEST_NUM; i++){
        sigma[i] = Schnorr::Sign(pp, sk[i], message);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "sign message takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++){
        if(Schnorr::Verify(pp, pk[i], message, sigma[i]) == false){
            std::cout << "the " << i << "th verification fails" << std::endl;
        }
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "verify signature takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;
}


int main()
{  
    CRYPTO_Initialize(); 
 
    
    std::ios::sync_with_stdio(false);

    PrintSplitLine('-'); 
    std::cout << "Schnorr SIG test begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    
    size_t TEST_NUM = 10000; 
    test_schnorr(TEST_NUM);
    
    PrintSplitLine('-'); 
    std::cout << "Schnorr SIG test finishes >>>" << std::endl; 
    PrintSplitLine('-'); 

  
    CRYPTO_Finalize(); 
    
    return 0; 
}



