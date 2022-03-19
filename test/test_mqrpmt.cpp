#include "../mpc/rpmt/cwprf_mqrpmt.hpp"


struct RPMTTestcase{
    size_t LEN; 
    size_t HAMMING_WEIGHT; 
    std::vector<block> vec_X; 
    std::vector<block> vec_Y;
    std::vector<uint8_t> vec_indication_bit; 
};

RPMTTestcase GenTestInstance(size_t LEN)
{
    RPMTTestcase testcase; 
    testcase.LEN = LEN; 
    testcase.HAMMING_WEIGHT = 0; 
    PRG::Seed seed; 
    PRG::SetSeed(seed, fix_key, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, LEN);
    testcase.vec_indication_bit = PRG::GenRandomBits(seed, LEN);  
    for(auto i = 0; i < LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_Y[i] = testcase.vec_X[i];
            testcase.HAMMING_WEIGHT++; 
        }
    }
    return testcase;
}

void SaveTestInstance(RPMTTestcase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << testcase.LEN; 
    fout << testcase.HAMMING_WEIGHT; 
    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_X[i]; 
    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_Y[i]; 
    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_indication_bit[i]; 

    fout.close(); 
}

void FetchTestInstance(RPMTTestcase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> testcase.LEN;
    fin >> testcase.HAMMING_WEIGHT; 
    testcase.vec_X.resize(testcase.LEN); 
    testcase.vec_Y.resize(testcase.LEN); 
    testcase.vec_indication_bit.resize(testcase.LEN); 
    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_X[i]; 
    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_Y[i]; 
    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_indication_bit[i];

    fin.close(); 
}


int main()
{
    Global_Setup(); 
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    PrintSplitLine('-'); 
    std::cout << "mqRPMT test begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "mqRPMT.pp"; 
    cwPRFmqRPMT::PP pp; 
    if(!FileExist(pp_filename)){
        pp = cwPRFmqRPMT::Setup("bloom", 40); // 40 is the statistical parameter
        cwPRFmqRPMT::SavePP(pp, pp_filename); 
    }
    else{
        cwPRFmqRPMT::FetchPP(pp, pp_filename); 
    }

    // set instance size
    size_t LEN = size_t(pow(2, 20)); 
    std::cout << "number of elements = " << LEN << std::endl; 

    std::string testcase_filename = "mqRPMT.testcase"; 
    RPMTTestcase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestInstance(LEN); 
        SaveTestInstance(testcase, testcase_filename); 
    }
    else{
        FetchTestInstance(testcase, testcase_filename);
    }

    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between server and client (hint: start server first) ==> ";  
    std::getline(std::cin, party); // first the server, then the client

  
    if(party == "server"){
        NetIO server("server", "", 8080);
        std::vector<uint8_t> vec_indication_bit_prime = cwPRFmqRPMT::Server(server, pp, testcase.vec_X, LEN);

        if(CompareBits(testcase.vec_indication_bit, vec_indication_bit_prime))
        {
            std::cout << "cwPRF-mqRPMT test succeeds" << std::endl; 
        }
        else{
            std::cout << "cwPRF-mqRPMT test fails" << std::endl; 
        }

        // size_t CARDINALITY = 0;
        // for(auto i = 0; i < LEN; i++){
        //     if(vec_indication_bit_prime[i] == 1) CARDINALITY++; 
        // } 
        // std::cout << testcase.HAMMING_WEIGHT << std::endl;
        // std::cout << CARDINALITY << std::endl;
    }

    if(party == "client")
    {
        NetIO client("client", "127.0.0.1", 8080);        
        cwPRFmqRPMT::Client(client, pp, testcase.vec_Y, LEN);
    } 

    PrintSplitLine('-'); 
    std::cout << "mqRPMT test ends >>>" << std::endl; 
    PrintSplitLine('-'); 

    ECGroup_Finalize(); 
    Context_Finalize();   
    return 0; 
}