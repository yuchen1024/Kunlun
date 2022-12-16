#define DEBUG

#include "../zkp/bulletproofs/bullet_proof.hpp"
#include "../crypto/setup.hpp"


void GenRandomBulletInstanceWitness(Bullet::PP &pp, Bullet::Instance &instance, Bullet::Witness &witness, bool STATEMENT_FLAG)
{
    if(STATEMENT_FLAG == true) std::cout << "generate a true statement pair" << std::endl; 
    else std::cout << "generate a random statement (false with overwhelming probability)" << std::endl; 
    BigInt exp = BigInt(pp.RANGE_LEN);

    BigInt bn_range_size = bn_2.ModExp(exp, order); // 2^exp 
    std::cout << "range = [" << 0 << "," << BN_bn2hex(bn_range_size.bn_ptr) <<")" << std::endl; 
    size_t n = instance.C.size();
    for(auto i = 0; i < n; i++)
    {
        witness.r[i] = GenRandomBigIntLessThan(order);
        witness.v[i] = GenRandomBigIntLessThan(order); 
        if (STATEMENT_FLAG == true){
            witness.v[i] = witness.v[i] % bn_range_size;  
        }
        instance.C[i] = pp.g * witness.r[i] + pp.h * witness.v[i]; 
    }
    std::cout << "random instance generation finished" << std::endl;
    PrintBigIntVector(witness.v, "witness.v");  
    PrintSplitLine('-');
}

void GenBoundaryBulletInstanceWitness(Bullet::PP &pp, Bullet::Instance &instance, Bullet::Witness &witness, std::string BOUNDARY_FLAG)
{  
    BigInt exp = BigInt(pp.RANGE_LEN);
    if (BOUNDARY_FLAG == "LEFT") std::cout << "generate left boundary" << std::endl;
    else std::cout << "generate right boundary" << std::endl;
    size_t n = instance.C.size();
    for(auto i = 0; i < n; i++)
    {
        witness.r[i] = GenRandomBigIntLessThan(order);
        if (BOUNDARY_FLAG == "LEFT"){
            witness.v[i] = bn_0;
        }
        else{
            witness.v[i] = bn_2.ModExp(exp, order) - bn_1;
        } 
        instance.C[i] = pp.g * witness.r[i] + pp.h * witness.v[i]; 
    }
    PrintBigIntVector(witness.v, "witness.v"); 
}

void test_bulletproof_boundary(size_t RANGE_LEN, size_t MAX_AGG_NUM, std::string BOUNDARY_FLAG)
{
    Bullet::PP pp = Bullet::Setup(RANGE_LEN, MAX_AGG_NUM);

    Bullet::Instance instance; 
    instance.C.resize(MAX_AGG_NUM); 
    Bullet::Witness witness; 
    witness.r.resize(MAX_AGG_NUM);
    witness.v.resize(MAX_AGG_NUM);
    Bullet::Proof proof; 
    

    PrintSplitLine('-'); 
    std::cout << "begin the test of bulletproofs >>>" << std::endl;
    PrintSplitLine('-'); 

    GenBoundaryBulletInstanceWitness(pp, instance, witness, BOUNDARY_FLAG); 

    std::string transcript_str; 
    
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet::Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-'); 
    
    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet::Verify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    
    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet::FastVerify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "fast proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    std::cout << "finish the test of bulletproofs >>>" << std::endl;
}


void test_bulletproof(size_t RANGE_LEN, size_t MAX_AGG_NUM, bool STATEMENT_FLAG)
{
    Bullet::PP pp = Bullet::Setup(RANGE_LEN, MAX_AGG_NUM);

    Bullet::Instance instance; 
    instance.C.resize(MAX_AGG_NUM); 
    Bullet::Witness witness; 
    witness.r.resize(MAX_AGG_NUM);
    witness.v.resize(MAX_AGG_NUM);
    Bullet::Proof proof; 

    PrintSplitLine('-'); 
    std::cout << "begin the test of bulletproofs >>>" << std::endl;
    PrintSplitLine('-'); 

    GenRandomBulletInstanceWitness(pp, instance, witness, STATEMENT_FLAG); 

    std::string transcript_str; 
    
    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet::Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "proof generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet::Verify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    start_time = std::chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet::FastVerify(pp, instance, transcript_str, proof);
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "fast proof verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
    std::cout << "finish the test of bulletproofs >>>" << std::endl;
    PrintSplitLine('-'); 
}


int main()
{ 
    CRYPTO_Initialize();  

    size_t RANGE_LEN = 32; // range size
    size_t MAX_AGG_NUM = 4;  // number of sub-argument

    test_bulletproof_boundary(RANGE_LEN, MAX_AGG_NUM, "LEFT");
    test_bulletproof_boundary(RANGE_LEN, MAX_AGG_NUM, "RIGHT");

    test_bulletproof(RANGE_LEN, MAX_AGG_NUM, false);
    test_bulletproof(RANGE_LEN, MAX_AGG_NUM, true);

    CRYPTO_Finalize(); 

    return 0;
}