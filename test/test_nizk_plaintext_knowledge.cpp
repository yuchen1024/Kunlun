//#define DEBUG

#include "../crypto/ec_point.hpp"
#include "../pke/twisted_elgamal.hpp"
#include "../nizk/nizk_plaintext_knowledge.hpp"


void GenRandomEncInstanceWitness(Plaintext_Knowledge_PP &pp, Plaintext_Knowledge_Instance &instance, 
                              Plaintext_Knowledge_Witness &witness)
{
    Print_SplitLine('-');  
    std::cout << "generate a valid twisted elgamal ciphertext >>>" << std::endl; 

    witness.r = GenRandomBigIntLessThan(order); 
    witness.v = GenRandomBigIntLessThan(order);

    instance.pk = GenRandomGenerator(); 
    Twisted_ElGamal_PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  

    Twisted_ElGamal_CT ct; 
    Twisted_ElGamal_Enc(enc_pp, instance.pk, witness.v, witness.r, ct); 
    instance.X = ct.X; 
    instance.Y = ct.Y;
}

void test_nizk_plaintext_knowledge()
{
    std::cout << "begin the test of NIZKPoK for plaintext knowledge >>>" << std::endl; 
    
    Plaintext_Knowledge_PP pp; 
    NIZK_Plaintext_Knowledge_Setup(pp);
    Plaintext_Knowledge_Instance instance;
    Plaintext_Knowledge_Witness witness; 
    Plaintext_Knowledge_Proof proof; 

    GenRandomEncInstanceWitness(pp, instance, witness); 

    std::string transcript_str; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    NIZK_Plaintext_Knowledge_Prove(pp, instance, witness, transcript_str, proof); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    NIZK_Plaintext_Knowledge_Verify(pp, instance, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

int main()
{
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);   
    
    test_nizk_plaintext_knowledge();

    ECGroup_Finalize(); 
    Context_Finalize(); 

    return 0; 
}



