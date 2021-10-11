#define DEBUG

#include "../crypto/ec_point.hpp"
#include "../pke/twisted_elgamal.hpp"
#include "../nizk/nizk_plaintext_equality.hpp"

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

    instance.pk1 = GenRandomGenerator();
    instance.pk2 = GenRandomGenerator();
    instance.pk3 = GenRandomGenerator();

    TwistedElGamal::PP enc_pp; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h; 
    TwistedElGamal::MRCT ct; 

    std::vector<ECPoint> vec_pk{instance.pk1, instance.pk2, instance.pk3};
     
    TwistedElGamal::Enc(enc_pp, vec_pk, witness.v, witness.r, ct); 
    
    instance.X1 = ct.X[0]; 
    instance.X2 = ct.X[1]; 
    instance.X3 = ct.X[2]; 
    instance.Y = ct.Y; 

    if(flag == false){
        ECPoint noisy = GenRandomGenerator();
        instance.Y = instance.Y + noisy;
    } 
}

void test_nizk_plaintext_equality(bool flag)
{
    PrintSplitLine('-');  
    std::cout << "begin the test of NIZKPoK for plaintext equality >>>" << std::endl; 

    PlaintextEquality::PP pp;   
    PlaintextEquality::Setup(pp);
    PlaintextEquality::Instance instance; 
    PlaintextEquality::Witness witness; 
    PlaintextEquality::Proof proof; 

    std::string transcript_str; 

    GenRandomTripleEncInstanceWitness(pp, instance, witness, flag); 
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    PlaintextEquality::Prove(pp, instance, witness, transcript_str, proof); 
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
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);   
    
    test_nizk_plaintext_equality(true);
    test_nizk_plaintext_equality(false); 

    ECGroup_Finalize(); 
    Context_Finalize(); 

    return 0; 
}



