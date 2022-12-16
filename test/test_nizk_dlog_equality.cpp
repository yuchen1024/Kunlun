#define DEBUG

#include "../zkp/nizk/nizk_dlog_equality.hpp"
#include "../crypto/setup.hpp"

void GenRandomDDHInstanceWitness(DLOGEquality::PP &pp, DLOGEquality::Instance &instance, 
                                 DLOGEquality::Witness &witness, bool flag)
{
    // generate a true statement (false with overwhelming probability)
    PrintSplitLine('-'); 
    if (flag == true){
        std::cout << "generate a DDH tuple >>>" << std::endl;
    } 
    else{
        std::cout << "generate a random tuple >>>" << std::endl; 
    } 
    witness.w = GenRandomBigIntLessThan(order);  

    instance.g1 = GenRandomGenerator(); 
    instance.g2 = GenRandomGenerator(); 

    instance.h1 = instance.g1 * witness.w; 
    instance.h2 = instance.g2 * witness.w; 

    if(flag == false){
        ECPoint noisy = GenRandomGenerator();
        instance.h2 = instance.h2 + noisy;
    } 
}

void test_nizk_dlog_equality(bool flag)
{
    PrintSplitLine('-');
    std::cout << "begin the test of dlog equality proof (standard version) >>>" << std::endl; 
    
    DLOGEquality::PP pp = DLOGEquality::Setup();
    DLOGEquality::Instance instance; 
    DLOGEquality::Witness witness;  


    std::string transcript_str;

    // test the standard version

    GenRandomDDHInstanceWitness(pp, instance, witness, flag); 
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = "";
    DLOGEquality::Proof proof = DLOGEquality::Prove(pp, instance, witness, transcript_str); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "DDH proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;


    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = "";
    DLOGEquality::Verify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "DDH proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    std::cout << "finish the test of dlog equality proof (standard version) >>>" << std::endl; 

}

int main()
{
    CRYPTO_Initialize();  
    
    test_nizk_dlog_equality(true);
    test_nizk_dlog_equality(false); 

    CRYPTO_Finalize(); 

    return 0; 
}



