#define DEBUG

#include "../pke/twisted_elgamal.hpp"
#include "../zkp/nizk/nizk_plaintext_equality.hpp"
#include "../crypto/setup.hpp"

void GenRandomTripleEncInstanceWitness(PlaintextEquality::PP &pp, PlaintextEquality::Instance &instance, 
                                       PlaintextEquality::Witness &witness, bool flag)
{
    PrintSplitLine('-');  
    if (flag == true){
        std::cout << "generate a well-formed 1-message 3-recipient twisted ElGamal ciphertext >>>" << std::endl; 
    } else{
        std::cout << ">>> generate an ill-formed 1-message 3-recipient twisted ElGamal ciphertext" << std::endl; 
    }

    witness.r = GenRandomBigIntLessThan(order);
    witness.v = GenRandomBigIntLessThan(order); 

    instance.vec_pk.resize(3);
    for(auto i = 0; i < instance.vec_pk.size(); i++){ 
        instance.vec_pk[i] = GenRandomGenerator();
    }


    TwistedElGamal::PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h; 
     
    instance.ct = TwistedElGamal::Enc(enc_pp, instance.vec_pk, witness.v, witness.r); 
    

    if(flag == false){
        ECPoint noisy = GenRandomGenerator();
        instance.ct.Y = instance.ct.Y + noisy;
    } 
}

void test_nizk_plaintext_equality(bool flag)
{
    PrintSplitLine('-');  
    std::cout << "begin the test of NIZKPoK for plaintext equality >>>" << std::endl; 

    TwistedElGamal::PP pp_enc = TwistedElGamal::Setup(32, 7); 
    PlaintextEquality::PP pp = PlaintextEquality::Setup(pp_enc);
    PlaintextEquality::Instance instance; 
    PlaintextEquality::Witness witness; 

    std::string transcript_str; 

    GenRandomTripleEncInstanceWitness(pp, instance, witness, flag); 
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    PlaintextEquality::Proof proof = PlaintextEquality::Prove(pp, instance, witness, transcript_str); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    PlaintextEquality::Verify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

int main()
{
    CRYPTO_Initialize();   
    
    test_nizk_plaintext_equality(true);
    test_nizk_plaintext_equality(false); 
 
    CRYPTO_Finalize(); 

    return 0; 
}



