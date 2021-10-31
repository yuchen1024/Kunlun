#include "../psu/dh-psu.hpp"

void GenPSUTestSet(std::vector<block> &vec_X, std::vector<block> &vec_Y, size_t LEN)
{
    PRG::Seed seed; 
    PRG::SetSeed(seed, fix_key, 0); // initialize PRG
    std::vector<block> vec_M0 = PRG::GenRandomBlocks(seed, LEN/2);
    std::vector<block> vec_M1 = PRG::GenRandomBlocks(seed, LEN/2);
    std::vector<block> vec_M2 = PRG::GenRandomBlocks(seed, LEN/2);
    
    vec_X.insert(vec_X.begin(), vec_M0.begin(), vec_M0.end());
    vec_X.insert(vec_X.end(), vec_M2.begin(), vec_M2.end());
    std::random_shuffle(vec_X.begin(), vec_X.end());

    vec_Y.insert(vec_Y.begin(), vec_M1.begin(), vec_M1.end());
    vec_Y.insert(vec_Y.end(), vec_M2.begin(), vec_M2.end());
    std::random_shuffle(vec_Y.begin(), vec_Y.end());
}

void test_psu(std::string party, size_t LEN) 
{
    PSU::PP pp; 
    PSU::Setup(pp, "bloom", 40); 

    std::vector<block> vec_X; 
    std::vector<block> vec_Y;

    GenPSUTestSet(vec_X, vec_Y, LEN);

    std::unordered_set<std::string> unionXY;
    std::unordered_set<std::string> unionXY_prime;

    for(auto i = 0; i < LEN; i++){
        unionXY.insert(Block::ToString(vec_X[i])); 
        unionXY.insert(Block::ToString(vec_Y[i])); 
    }

    if(party == "sender"){
        NetIO server("server", "", 8080);
        auto start_time = std::chrono::steady_clock::now();  
        PSU::ParallelPipelineSender(server, pp, vec_X, LEN);
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "PSU takes time= " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    }

    if(party == "receiver")
    {
        NetIO client("client", "192.168.0.12", 8080); 
        auto start_time = std::chrono::steady_clock::now(); 
        PSU::ParallelPipelineReceiver(client, pp, vec_Y, LEN, unionXY_prime); 
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "PSU takes time= " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

        std::cout << "unionXY size = " << unionXY.size() << std::endl;
        std::cout << "unionXY' size = " << unionXY_prime.size() << std::endl;
        if(unionXY == unionXY_prime)
        {
            std::cout << "PSU test succeeds" << std::endl; 
        }
        else{
            std::cout << "PSU test fails" << std::endl; 
        }
    }

}


int main()
{
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    //test_hash_to_point(1024*1024); 
    //test_fast_hash_to_point(1024*1024); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: start sender first) ==> ";  
    std::getline(std::cin, party); // first sender (acts as server), then receiver (acts as client)
 
    size_t LEN = size_t(pow(2, 20)); 
    
    std::cout << "#elements = " << LEN << std::endl; 
    test_psu(party, LEN);


    ECGroup_Finalize(); 
    Context_Finalize();   
    return 0; 
}