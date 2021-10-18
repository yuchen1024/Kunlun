#include "../psi/dh-psi.hpp"

void GenPSITestSet(std::vector<block> &vec_X, std::vector<block> &vec_Y, size_t LEN)
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

void test_psi(std::string party, size_t LEN) 
{
    PSI::PP pp; 
    PSI::Setup(pp); 

    std::vector<block> vec_X; 
    std::vector<block> vec_Y;

    GenPSITestSet(vec_X, vec_Y, LEN);

    std::vector<std::string> setX(LEN);
    std::vector<std::string> setY(LEN);
    for(auto i = 0; i < LEN; i++){
        setX[i] = Block::ToString(vec_X[i]); 
        setY[i] = Block::ToString(vec_Y[i]); 
    }

    std::sort (setX.begin(), setX.end());    
    std::sort (setY.begin(), setY.end()); 

    std::vector<std::string> temp_intersection;

    std::set_intersection(setX.begin(), setX.end(), setY.begin(), setY.end(), std::back_inserter(temp_intersection));


    std::unordered_set<std::string> intersectionXY;
    for(auto i = 0; i < temp_intersection.size(); i++)
        intersectionXY.insert(temp_intersection[i]); 

    std::unordered_set<std::string> intersectionXY_prime;


    if(party == "sender"){
        // std::cout << "the len = " << LEN << std::endl; 

        auto start_time = std::chrono::steady_clock::now(); 
        NetIO server("server", "", 8080); 
        PSI::PipelineSender(server, pp, vec_X, LEN);
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "PSI takes time= " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    }

    if(party == "receiver")
    {
        auto start_time = std::chrono::steady_clock::now(); 
        NetIO client("client", "127.0.0.1", 8080); 
        PSI::PipelineReceiver(client, pp, vec_Y, LEN, intersectionXY_prime); 
        auto end_time = std::chrono::steady_clock::now(); 
        auto running_time = end_time - start_time;
        std::cout << "PSI takes time= " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

        std::cout << "intersectionXY size = " << intersectionXY.size() << std::endl;
        std::cout << "intersectionXY' size = " << intersectionXY_prime.size() << std::endl;
        if(intersectionXY == intersectionXY_prime)
        {
            std::cout << "PSI test succeeds" << std::endl; 
        }
        else{
            std::cout << "PSI test fails" << std::endl; 
        }
    }

}


int main()
{
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    //test_hash_to_point(1024*1024); 


    std::string party;
    std::cout << "please select your role between sender and receiver (hint: start sender first) ==> ";  
    std::getline(std::cin, party); // first sender (acts as server), then receiver (acts as client)
    
    // auto start_time = std::chrono::steady_clock::now(); 
    size_t LEN = size_t(pow(2, 20)); 
    std::cout << "LEN = " << LEN << std::endl;  
    test_psi(party, LEN);


    ECGroup_Finalize(); 
    Context_Finalize();   
    return 0; 
}