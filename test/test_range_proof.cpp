#define DEBUG

#include "../gadget/range_proof.hpp"
#include "../crypto/setup.hpp"


void GenRandomGadget1InstanceWitness(Gadget::PP &pp, Gadget::Instance &instance, Gadget::Witness_type1 &witness)
{
    std::cout << "generate a random gadget-1 instance-witness pair" << std::endl;  
    BigInt exp = BigInt(pp.bullet_part.RANGE_LEN);
    BigInt bn_range_size = bn_2.ModExp(exp, order); // 2^exp 
    std::cout << "range = [" << 0 << "," << BN_bn2hex(bn_range_size.bn_ptr) <<")" << std::endl;

    witness.r = GenRandomBigIntLessThan(order); 
    witness.m = GenRandomBigIntLessThan(bn_range_size);

    instance.pk = GenRandomGenerator();
    instance.ct = TwistedElGamal::Enc(pp.enc_part, instance.pk, witness.m, witness.r); 
    std::cout << "random gadget-1 instance witness generation finished" << std::endl;
    witness.m.Print("plaintext");  
    PrintSplitLine('-');
}


void GenRandomGadget2InstanceWitness(Gadget::PP &pp, Gadget::Instance &instance, Gadget::Witness_type2 &witness)
{
    std::cout << "generate a random gadget-2 instance-witness pair" << std::endl;  
    BigInt exp = BigInt(pp.bullet_part.RANGE_LEN);
    BigInt bn_range_size = bn_2.ModExp(exp, order); // 2^exp 
    std::cout << "range = [" << 0 << "," << BN_bn2hex(bn_range_size.bn_ptr) <<")" << std::endl;


    std::tie(instance.pk, witness.sk) = TwistedElGamal::KeyGen(pp.enc_part); 

    BigInt m = GenRandomBigIntLessThan(bn_range_size);
    TwistedElGamal::CT ct = TwistedElGamal::Enc(pp.enc_part, instance.pk, m);  
 
    instance.ct = ct;  
    std::cout << "random gadget-2 instance witness pair generation finished" << std::endl;
    
    m.Print("plaintext");  
    PrintSplitLine('-');
}

void test_gadget1(BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, size_t &RANGE_LEN, size_t &AGG_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the test of gadget-1 >>>" << std::endl;
    LEFT_BOUND.Print("LEFT_BOUND");
    RIGHT_BOUND.Print("RIGHT_BOUND");
    PrintSplitLine('-'); 

    Bullet::PP pp_bullet = Bullet::Setup(RANGE_LEN, AGG_NUM); 
    size_t DEC_THREAD_NUM = 8; 
    size_t TRADEOFF_NUM = 7;
    TwistedElGamal::PP pp_enc = TwistedElGamal::Setup(RANGE_LEN, TRADEOFF_NUM); 

    Gadget::PP pp = Gadget::Setup(pp_enc, pp_bullet);
    Gadget::Instance instance; 
    Gadget::Witness_type1 witness; 
    GenRandomGadget1InstanceWitness(pp, instance, witness);
 
    std::string transcript_str; 
    
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget::Proof_type1 proof = Gadget::Prove(pp, instance, LEFT_BOUND, RIGHT_BOUND, witness, transcript_str); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget::Verify(pp, instance, LEFT_BOUND, RIGHT_BOUND,  transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    std::cout << "finish the test of gadget-1 >>>" << std::endl;
    PrintSplitLine('-'); 
}

void test_gadget2(BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, size_t &RANGE_LEN, size_t &AGG_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "begin the test of gadget-2 >>>" << std::endl;
    LEFT_BOUND.Print("LEFT_BOUND");
    RIGHT_BOUND.Print("RIGHT_BOUND");
    PrintSplitLine('-'); 

    Bullet::PP pp_bullet = Bullet::Setup(RANGE_LEN, AGG_NUM); 
    size_t DEC_THREAD_NUM = 8; 
    size_t TRADEOFF_NUM = 7;
    TwistedElGamal::PP pp_enc = TwistedElGamal::Setup(RANGE_LEN, TRADEOFF_NUM); 
    Gadget::PP pp = Gadget::Setup(pp_enc, pp_bullet);
    Gadget::Instance instance; 
    Gadget::Witness_type2 witness; 
    GenRandomGadget2InstanceWitness(pp, instance, witness);
    Gadget::Proof_type2 proof;  
    std::string transcript_str; 
    
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget::Prove(pp, instance, LEFT_BOUND, RIGHT_BOUND, witness, transcript_str, proof); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget::Verify(pp, instance, LEFT_BOUND, RIGHT_BOUND, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    std::cout << "finish the test of gadget-2 >>>" << std::endl;
    PrintSplitLine('-'); 
}


int main()
{ 
    CRYPTO_Initialize(); 

    size_t RANGE_LEN = 32; // range size
    size_t AGG_NUM = 2; 

    BigInt LEFT_BOUND = uint64_t(pow(2,10)); 
    BigInt RIGHT_BOUND = uint64_t(pow(2, 32)); 
    
    test_gadget1(LEFT_BOUND, RIGHT_BOUND, RANGE_LEN, AGG_NUM); 
    test_gadget2(LEFT_BOUND, RIGHT_BOUND, RANGE_LEN, AGG_NUM); 

    CRYPTO_Finalize(); 

    return 0; 
}