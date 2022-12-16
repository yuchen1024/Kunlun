#define DEBUG

#include "../zkp/bulletproofs/innerproduct_proof.hpp"
#include "../crypto/setup.hpp"

// generate a random instance-witness pair
void GenRandomInnerProductInstanceWitness(InnerProduct::PP &pp, InnerProduct::Instance &instance, InnerProduct::Witness &witness)
{ 

    std::cout << "generate random (instance, witness) pair >>>" << std::endl;  

    // InnerProduct_Instance_new(instance); 
    witness.vec_a = GenRandomBigIntVectorLessThan(pp.VECTOR_LEN, BigInt(order)); 
    witness.vec_b = GenRandomBigIntVectorLessThan(pp.VECTOR_LEN, BigInt(order)); 

    //instance.u = GenRandomGenerator();
    BigInt c = BigIntVectorModInnerProduct(witness.vec_a, witness.vec_b, BigInt(order)); 

    instance.P = pp.u * c;  // P = u^c
 
    instance.P = instance.P + ECPointVectorMul(pp.vec_g, witness.vec_a) + ECPointVectorMul(pp.vec_h, witness.vec_b);
}

void test_innerproduct_proof()
{
    PrintSplitLine('-');
    std::cout << "begin the test of innerproduct proof >>>" << std::endl; 
    
    size_t VECTOR_LEN = 32; 

    InnerProduct::PP pp = InnerProduct::Setup(VECTOR_LEN, true);
    
    InnerProduct::Instance instance; 
    InnerProduct::Witness witness; 

    GenRandomInnerProductInstanceWitness(pp, instance, witness); 


    InnerProduct::Proof proof; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    std::string transcript_str = ""; 
    transcript_str += instance.P.ToByteString(); 

    InnerProduct::Prove(pp, instance, witness, transcript_str, proof);
    
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "inner-product proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    transcript_str += instance.P.ToByteString(); 
    InnerProduct::Verify(pp, instance, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "inner-product proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    transcript_str += instance.P.ToByteString(); 
    InnerProduct::FastVerify(pp, instance, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "fast inner-product proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    std::cout << "finish the test of innerproduct proof >>>" << std::endl; 
}

int main()
{
    CRYPTO_Initialize();  
    
    test_innerproduct_proof();

    CRYPTO_Finalize(); 

    return 0; 
}