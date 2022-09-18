//#define DEBUG
#include "../utility/print.hpp"

#include <mcl/ec.hpp>


struct TagZn;
typedef mcl::FpT<> Fp;
typedef mcl::FpT<TagZn> Zn;
typedef mcl::EcT<Fp> Ec;


void benchmark_mcl_ecc(size_t TEST_NUM)
{
    PrintSplitLine('-'); 
    std::cout << "MCL ECC benchmark test begins >>>" << std::endl; 
    PrintSplitLine('-'); 

    Ec g; 
    mcl::initCurve<Ec, Zn>(MCL_SECP256K1, &g); 
    //mcl::initCurve<Ec, Zn>(MCL_NIST_P256, &g);
    
    Ec A[TEST_NUM]; 
    Ec B[TEST_NUM]; 
    Ec C[TEST_NUM];
    Zn r[TEST_NUM];

    Zn sk; 
    Ec pk; 

    sk.setRand();
    Ec::mul(pk, g, sk);  

    size_t winSize = 7;
    size_t bitSize = Zn::getBitSize(); 
    mcl::fp::WindowMethod<Ec> wm_g;
    wm_g.init(g, bitSize, winSize);


    for(auto i = 0; i < TEST_NUM; i++){
        r[i].setRand(); 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    for(auto i = 0; i < TEST_NUM; i++){
        wm_g.mul(A[i], r[i]);
    }
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "fixed point exp with precomputation takes = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    start_time = std::chrono::steady_clock::now(); 

    for(auto i = 0; i < TEST_NUM; i++){
        Ec::mul(B[i], pk, r[i]);
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "fixed point exp without precomputation takes = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    
    start_time = std::chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
        Ec::add(C[i], A[i], B[i]); 
    }
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "point add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/TEST_NUM << " ms" << std::endl;


    PrintSplitLine('-'); 
    std::cout << "ECC benchmark test finishes <<<<<<" << std::endl; 
    PrintSplitLine('-'); 
}

int main()
{
    size_t TEST_NUM = 10000;  
    benchmark_mcl_ecc(TEST_NUM); 
 
    return 0; 
}

