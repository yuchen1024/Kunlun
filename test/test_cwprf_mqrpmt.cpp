#include "../mpc/rpmt/cwprf_mqrpmt.hpp"
#include "../crypto/setup.hpp"

struct RPMTTestcase{
    size_t LOG_SERVER_LEN; 
    size_t SERVER_LEN;

    size_t LOG_CLIENT_LEN; 
    size_t CLIENT_LEN;

    size_t HAMMING_WEIGHT; 
    std::vector<block> vec_X; 
    std::vector<block> vec_Y;
    std::vector<uint8_t> vec_indication_bit; 
};

RPMTTestcase GenTestInstance(size_t LOG_SERVER_LEN, size_t LOG_CLIENT_LEN)
{
    RPMTTestcase testcase; 
    
    testcase.LOG_SERVER_LEN = LOG_SERVER_LEN;
    testcase.SERVER_LEN = size_t(pow(2, testcase.LOG_SERVER_LEN)); 
    testcase.LOG_CLIENT_LEN = LOG_CLIENT_LEN;
    testcase.CLIENT_LEN = size_t(pow(2, testcase.LOG_CLIENT_LEN)); 

    // set the Hamming weight to be a half of the CLIENT_LEN
    testcase.HAMMING_WEIGHT = testcase.CLIENT_LEN/2;

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.CLIENT_LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.SERVER_LEN);

    // generate a random indication bit vector conditioned on given Hamming weight
    testcase.vec_indication_bit.resize(testcase.CLIENT_LEN);  
    for(auto i = 0; i < testcase.CLIENT_LEN; i++){
        if(i < testcase.HAMMING_WEIGHT) testcase.vec_indication_bit[i] = 1; 
        else testcase.vec_indication_bit[i] = 0; 
    }
    std::shuffle(testcase.vec_indication_bit.begin(), testcase.vec_indication_bit.end(), global_built_in_prg);

    // adjust vec_X and vec_Y
    for(auto i = 0, j = 0; i < testcase.CLIENT_LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_X[i] = testcase.vec_Y[j];
            j++; 
        }
    }
    std::shuffle(testcase.vec_Y.begin(), testcase.vec_Y.end(), global_built_in_prg);

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
    fout << testcase.LOG_SERVER_LEN; 
    fout << testcase.SERVER_LEN;
    fout << testcase.LOG_CLIENT_LEN; 
    fout << testcase.CLIENT_LEN;

    fout << testcase.HAMMING_WEIGHT; 
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_indication_bit; 

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
    fin >> testcase.LOG_SERVER_LEN; 
    fin >> testcase.SERVER_LEN;
    fin >> testcase.LOG_CLIENT_LEN; 
    fin >> testcase.CLIENT_LEN;

    fin >> testcase.HAMMING_WEIGHT; 
    testcase.vec_X.resize(testcase.CLIENT_LEN); 
    testcase.vec_Y.resize(testcase.SERVER_LEN); 
    testcase.vec_indication_bit.resize(testcase.CLIENT_LEN); 

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_indication_bit; 

    fin.close(); 
}


int main()
{
    CRYPTO_Initialize(); 

    PrintSplitLine('-'); 
    std::cout << "cwPRF-based mqRPMT test begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "generate or load public parameters and test case" << std::endl;

    size_t LOG_SERVER_LEN = 20;
    size_t LOG_CLIENT_LEN = 20; 
    size_t statistical_parameter = 40; 
    // generate pp (must be same for both server and client)
    std::string pp_filename = "cwPRFmqRPMT.pp"; 
    cwPRFmqRPMT::PP pp; 
    if(!FileExist(pp_filename)){
        pp = cwPRFmqRPMT::Setup(statistical_parameter, LOG_SERVER_LEN, LOG_CLIENT_LEN); 
        cwPRFmqRPMT::SavePP(pp, pp_filename); 
    }
    else{
        cwPRFmqRPMT::FetchPP(pp, pp_filename); 
    }

    std::cout << "size of Server's set = " << pp.SERVER_LEN << std::endl; 
    std::cout << "size of Client's set = " << pp.CLIENT_LEN << std::endl; 

    std::string testcase_filename = "cwPRFmqRPMT.testcase"; 
    RPMTTestcase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestInstance(pp.LOG_SERVER_LEN, pp.LOG_CLIENT_LEN); 
        SaveTestInstance(testcase, testcase_filename); 
    }
    else{
        FetchTestInstance(testcase, testcase_filename);
        if((pp.LOG_SERVER_LEN != testcase.LOG_SERVER_LEN) || (pp.LOG_CLIENT_LEN != testcase.LOG_CLIENT_LEN)) {
            std::cerr << "public parameters and testcase do not match" << std::endl; 
            exit(1); 
        }
    }

    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between server and client (hint: first start server, then start client) ==> ";  
    std::getline(std::cin, party); // first the server, then the client
    PrintSplitLine('-'); 
  
    if(party == "server"){
        NetIO server("server", "", 8080);
        std::vector<uint8_t> vec_indication_bit_real;
        
        vec_indication_bit_real = cwPRFmqRPMT::Server(server, pp, testcase.vec_Y);

        size_t HAMMING_WEIGHT = 0;
        for(auto i = 0; i < pp.CLIENT_LEN; i++){
            if(vec_indication_bit_real[i] == 1) HAMMING_WEIGHT++; 
        } 
        std::cout << "correct Hamming weight = " << testcase.HAMMING_WEIGHT << std::endl;
        std::cout << "real Hamming weight = " << HAMMING_WEIGHT << std::endl;

        double error_probability = abs(double(testcase.HAMMING_WEIGHT)-double(HAMMING_WEIGHT))/double(testcase.HAMMING_WEIGHT); 
        std::cout << "cwPRF-based mqRPMT test succeeds with probability " << (1 - error_probability) << std::endl; 
    }

    if(party == "client")
    {
        NetIO client("client", "127.0.0.1", 8080);  
        cwPRFmqRPMT::Client(client, pp, testcase.vec_X);
    } 

    PrintSplitLine('-'); 
    std::cout << "cwPRF-based mqRPMT test ends >>>" << std::endl; 
    PrintSplitLine('-'); 

    CRYPTO_Finalize();   
    
    return 0; 
}
