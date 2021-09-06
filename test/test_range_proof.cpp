#define DEBUG

#include "../gadget/range_proof.hpp"


void GenRandomGadget1InstanceWitness(Gadget_PP &pp, Gadget_Instance &instance, Gadget1_Witness &witness)
{
    std::cout << "generate a random gadget-1 instance-witness pair" << std::endl;  
    BigInt exp = BigInt(pp.RANGE_LEN);
    BigInt bn_range_size = bn_2.ModExp(exp, order); // 2^exp 
    std::cout << "range = [" << 0 << "," << BN_bn2hex(bn_range_size.bn_ptr) <<")" << std::endl;

    witness.r = GenRandomBigIntLessThan(order); 
    witness.m = GenRandomBigIntLessThan(bn_range_size);

    instance.pk = GenRandomGenerator();
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(pp, enc_pp);
    Twisted_ElGamal_Enc(enc_pp, instance.pk, witness.m, witness.r, instance.ct); 
    std::cout << "random gadget-1 instance witness generation finished" << std::endl;
    witness.m.Print("plaintext");  
    Print_SplitLine('-');
}


void GenRandomGadget2InstanceWitness(Gadget_PP &pp, Gadget_Instance &instance, Gadget2_Witness &witness)
{
    std::cout << "generate a random gadget-2 instance-witness pair" << std::endl;  
    BigInt exp = BigInt(pp.RANGE_LEN);
    BigInt bn_range_size = bn_2.ModExp(exp, order); // 2^exp 
    std::cout << "range = [" << 0 << "," << BN_bn2hex(bn_range_size.bn_ptr) <<")" << std::endl;

    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_Gadget_PP(pp, enc_pp); 
    Twisted_ElGamal_KP keypair; 
    Twisted_ElGamal_KeyGen(enc_pp, keypair); 

    BigInt m = GenRandomBigIntLessThan(bn_range_size);
    Twisted_ElGamal_CT ct; 
    Twisted_ElGamal_Enc(enc_pp, keypair.pk, m, ct);  
 
    witness.sk = keypair.sk; 

    instance.pk = keypair.pk; 
    instance.ct = ct;  
    std::cout << "random gadget-2 instance witness pair generation finished" << std::endl;
    
    m.Print("plaintext");  
    Print_SplitLine('-');
}

void test_gadget1(BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, size_t &RANGE_LEN, size_t &AGG_NUM, size_t &THREAD_NUM, size_t &TRADEOFF_NUM)
{
    Print_SplitLine('-'); 
    std::cout << "begin the test of gadget-1 >>>" << std::endl;
    LEFT_BOUND.Print("LEFT_BOUND");
    RIGHT_BOUND.Print("RIGHT_BOUND");
    Print_SplitLine('-'); 

    Gadget_PP pp; 
    Gadget_Setup(pp, RANGE_LEN, AGG_NUM, TRADEOFF_NUM, THREAD_NUM);
    Gadget_Instance instance; 
    Gadget1_Witness witness; 
    GenRandomGadget1InstanceWitness(pp, instance, witness);
    Gadget1_Proof proof;  
    std::string transcript_str; 
    
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget1_Prove(pp, instance, LEFT_BOUND, RIGHT_BOUND, witness, transcript_str, proof); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget1_Verify(pp, instance, LEFT_BOUND, RIGHT_BOUND,  transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    Print_SplitLine('-'); 
    std::cout << "finish the test of gadget-1 >>>" << std::endl;
    Print_SplitLine('-'); 
}

void test_gadget2(BigInt &LEFT_BOUND, BigInt &RIGHT_BOUND, 
                  size_t &RANGE_LEN, size_t &AGG_NUM, size_t &THREAD_NUM, size_t &TRADEOFF_NUM)
{
    Print_SplitLine('-'); 
    std::cout << "begin the test of gadget-2 >>>" << std::endl;
    LEFT_BOUND.Print("LEFT_BOUND");
    RIGHT_BOUND.Print("RIGHT_BOUND");
    Print_SplitLine('-'); 

    Gadget_PP pp; 
    Gadget_Setup(pp, RANGE_LEN, AGG_NUM, TRADEOFF_NUM, THREAD_NUM);
    Gadget_Instance instance; 
    Gadget2_Witness witness; 
    GenRandomGadget2InstanceWitness(pp, instance, witness);
    Gadget2_Proof proof;  
    std::string transcript_str; 
    
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget2_Prove(pp, instance, LEFT_BOUND, RIGHT_BOUND, witness, transcript_str, proof); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Gadget2_Verify(pp, instance, LEFT_BOUND, RIGHT_BOUND, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    Print_SplitLine('-'); 
    std::cout << "finish the test of gadget-2 >>>" << std::endl;
    Print_SplitLine('-'); 
}


int main()
{ 
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);   

    size_t RANGE_LEN = 32; // range size
    size_t AGG_NUM = 2; 
    size_t TRADEOFF_NUM = 7; 
    size_t THREAD_NUM = 4; 

    BigInt LEFT_BOUND = uint64_t(pow(2,10)); 
    BigInt RIGHT_BOUND = uint64_t(pow(2, 32)); 
    
    test_gadget1(LEFT_BOUND, RIGHT_BOUND, RANGE_LEN, AGG_NUM, THREAD_NUM, TRADEOFF_NUM); 
    test_gadget2(LEFT_BOUND, RIGHT_BOUND, RANGE_LEN, AGG_NUM, THREAD_NUM, TRADEOFF_NUM); 

    ECGroup_Finalize(); 
    Context_Finalize(); 

    return 0; 
}