#define DEBUG

#include "../bulletproofs/innerproduct_proof.hpp"

// generate a random instance-witness pair
void GenRandomInnerProductInstanceWitness(InnerProduct_PP &pp, InnerProduct_Instance &instance, InnerProduct_Witness &witness)
{ 

    std::cout << "generate random (instance, witness) pair >>>" << std::endl;  

    // InnerProduct_Instance_new(instance); 
    witness.vec_a.resize(pp.VECTOR_LEN); 
    witness.vec_b.resize(pp.VECTOR_LEN); 
    GenRandomBigIntVectorLessThan(witness.vec_a, order); 
    GenRandomBigIntVectorLessThan(witness.vec_b, order); 

    //instance.u = GenRandomGenerator();
    BigInt c = BigIntVector_ModInnerProduct(witness.vec_a, witness.vec_b); 

    instance.P = pp.u * c;  // P = u^c
 
    instance.P = instance.P + ECPointVector_Mul(pp.vec_g, witness.vec_a) + ECPointVector_Mul(pp.vec_h, witness.vec_b);
}

void test_innerproduct_proof()
{
    std::cout << "begin the test of innerproduct proof >>>" << std::endl; 
    
    InnerProduct_PP pp; 
    size_t VECTOR_LEN = 32; 

    InnerProduct_Setup(pp, VECTOR_LEN, true);
    
    InnerProduct_Instance instance; 
    InnerProduct_Witness witness; 

    GenRandomInnerProductInstanceWitness(pp, instance, witness); 
    InnerProduct_Proof proof; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    std::string transcript_str = ""; 
    transcript_str += ECPointToByteString(instance.P); 

    InnerProduct_Prove(pp, instance, witness, transcript_str, proof);
    
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    //Print_InnerProduct_Proof(proof); 
    
    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    transcript_str += ECPointToByteString(instance.P); 
    InnerProduct_Verify(pp, instance, transcript_str, proof); 
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "fast proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    std::cout << "finish the test of innerproduct proof >>>" << std::endl; 
}

int main()
{
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);   

    // std::cout << "hehe" << std::endl; 
    
    test_innerproduct_proof();

    ECGroup_Finalize(); 
    Context_Finalize(); 

    return 0; 
}