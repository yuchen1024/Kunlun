#define DEBUG

#include "../zkp/nizk/nizk_enc_relation.hpp"
#include "../crypto/setup.hpp"


void GenRandomEncInstanceWitness(EncRelation::PP &pp, EncRelation::Instance &instance, 
                                 EncRelation::Witness &witness, bool flag)
{
    PrintSplitLine('-');  

    size_t N = 8; 

    srand(time(0));
    witness.l = rand() % N; 

    std::vector<ECPoint> vec_m = GenRandomECPointVector(N); 
    std::vector<BigInt> vec_r = GenRandomBigIntVectorLessThan(N, order);
    instance.vec_CT.resize(N);  
    instance.ek = GenRandomECPoint(); 

    for(auto i = 0; i < N; i++){         
        instance.vec_CT[i] = TwistedElGamal::Enc(pp.enc_part, instance.ek, vec_m[i], vec_r[i]); 
    }

    if (flag == true)
    {
        std::cout << "generate " << N <<" well-formed ciphertexts >>>" << std::endl;
        ECPoint m; 
        m.SetInfinity();
        instance.vec_CT[witness.l] = TwistedElGamal::Enc(pp.enc_part, instance.ek, m, vec_r[witness.l]); 
    } 
    else
    {
        std::cout << "generate " << N <<" ill-formed ciphertexts >>>" << std::endl; 
    }

    witness.r = vec_r[witness.l];
}

void test_nizk_enc_relation(bool flag)
{
    PrintSplitLine('-');  
    std::cout << "begin the test of NIZKPoK for enc relation >>>" << std::endl; 

    size_t N_max = 32; 
    Pedersen::PP com_pp = Pedersen::Setup(N_max); 

 
    size_t MSG_LEN = 32; 
    size_t TRADEOFF_NUM = 7; 
    size_t DEC_THREAD_NUM = 8;
    TwistedElGamal::PP enc_pp = TwistedElGamal::Setup(MSG_LEN, TRADEOFF_NUM); 


    size_t n = 2;
    EncRelation::PP pp = EncRelation::Setup(com_pp, enc_pp, n);

    EncRelation::Instance instance; 
    EncRelation::Witness witness; 

    std::string transcript_str; 

    GenRandomEncInstanceWitness(pp, instance, witness, flag); 
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 

    EncRelation::Proof proof = EncRelation::Prove(pp, instance, witness, transcript_str); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    EncRelation::Verify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

int main()
{
    CRYPTO_Initialize();  
    
    test_nizk_enc_relation(true);
    test_nizk_enc_relation(false); 

    CRYPTO_Finalize(); 

    return 0; 
}



