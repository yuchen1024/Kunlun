//#define DEBUG

#include "../pke/twisted_elgamal.hpp"
#include "../zkp/nizk/nizk_plaintext_knowledge.hpp"
#include "../crypto/setup.hpp"


void GenRandomEncInstanceWitness(PlaintextKnowledge::PP &pp, PlaintextKnowledge::Instance &instance, 
                                 PlaintextKnowledge::Witness &witness)
{
    PrintSplitLine('-');  
    std::cout << "generate a valid twisted elgamal ciphertext >>>" << std::endl; 

    witness.r = GenRandomBigIntLessThan(order); 
    witness.v = GenRandomBigIntLessThan(order);

    instance.pk = GenRandomGenerator(); 
    TwistedElGamal::PP pp_enc; 
    pp_enc.g = pp.g; 
    pp_enc.h = pp.h;  

    instance.ct = TwistedElGamal::Enc(pp_enc, instance.pk, witness.v, witness.r); 
}

void test_nizk_plaintext_knowledge()
{
    std::cout << "begin the test of NIZKPoK for plaintext knowledge >>>" << std::endl; 
    
    TwistedElGamal::PP pp_enc = TwistedElGamal::Setup(32, 7); 
    PlaintextKnowledge::PP pp = PlaintextKnowledge::Setup(pp_enc);
    PlaintextKnowledge::Instance instance;
    PlaintextKnowledge::Witness witness; 

    GenRandomEncInstanceWitness(pp, instance, witness); 

    std::string transcript_str; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    PlaintextKnowledge::Proof proof = PlaintextKnowledge::Prove(pp, instance, witness, transcript_str); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    PlaintextKnowledge::Verify(pp, instance, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

int main()
{
    CRYPTO_Initialize(); 
    
    test_nizk_plaintext_knowledge();

    CRYPTO_Finalize(); 

    return 0; 
}

