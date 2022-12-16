#define DEBUG

#include "../signature/accountable_ring_sig.hpp"
#include "../crypto/setup.hpp"


void test_accountable_ring_sig()
{
    PrintSplitLine('-');  
    std::cout << "begin the test of accoutable ring signature >>>" << std::endl; 

    AccountableRingSig::PP pp; 
    AccountableRingSig::SP sp;
    size_t N_max = 32; 
    std::tie(pp, sp) = AccountableRingSig::Setup(N_max); 

    size_t N = 8; // ring size
    std::vector<ECPoint> vk_ring(N);
    std::vector<BigInt> sk_ring(N); 
    for(auto i = 0; i < N; i++){
        std::tie(vk_ring[i], sk_ring[i]) = AccountableRingSig::KeyGen(pp); 
    }
    srand(time(0));
    size_t index = rand() % N; 

    std::string message = "I am a hacker"; 
    AccountableRingSig::Signature sigma; 
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    sigma = AccountableRingSig::Sign(pp, sk_ring[index], vk_ring, message);
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "size-" << N << " acountable ring signature generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    AccountableRingSig::Verify(pp, vk_ring, message, sigma);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "size-" << N << " acountable ring signature verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    DLOGEquality::Proof correct_decryption_proof;
    ECPoint vk; 
    std::tie(vk, correct_decryption_proof) = AccountableRingSig::Open(pp, sp, vk_ring, sigma);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "size-" << N << " acountable ring signature open takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    AccountableRingSig::Justify(pp, vk_ring, sigma, vk, correct_decryption_proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "size-" << N << " acountable ring signature justify takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

}

int main()
{
    CRYPTO_Initialize(); 
    
    test_accountable_ring_sig();

    CRYPTO_Finalize(); 

    return 0; 
}



