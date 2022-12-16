#define DEBUG

#include "../zkp/nizk/nizk_dlog_knowledge.hpp"
#include "../crypto/setup.hpp"

void GenRandomDLOGInstanceWitness(DLOGKnowledge::PP &pp, DLOGKnowledge::Instance &instance, DLOGKnowledge::Witness &witness)
{
    // generate a true statement (false with overwhelming probability)
    PrintSplitLine('-'); 
    std::cout << "generate a random DLOG tuple >>>" << std::endl;

    witness.w = GenRandomBigIntLessThan(order);  
    instance.g = GenRandomGenerator();  
    instance.h = instance.g * witness.w; 
}

void test_nizk_dlog_knowledge()
{
    PrintSplitLine('-');
    std::cout << "begin the test of dlog knowledge proof (standard version) >>>" << std::endl; 
    
    DLOGKnowledge::PP pp = DLOGKnowledge::Setup();
    DLOGKnowledge::Instance instance; 
    DLOGKnowledge::Witness witness; 

    std::string transcript_str;

    // test the standard version

    GenRandomDLOGInstanceWitness(pp, instance, witness); 
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = "";
    DLOGKnowledge::Proof proof = DLOGKnowledge::Prove(pp, instance, witness, transcript_str); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "DLOG proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;


    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = "";
    DLOGKnowledge::Verify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "DLOG proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    std::cout << "finish the test of dlog knowledge proof (standard version) >>>" << std::endl; 

}

int main()
{
    CRYPTO_Initialize();   
    
    test_nizk_dlog_knowledge();

    CRYPTO_Finalize(); 

    return 0; 
}



