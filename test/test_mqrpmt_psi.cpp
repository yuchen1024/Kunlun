#include "../mpc/pso/mqrpmt_psi.hpp"
#include "../crypto/setup.hpp"


struct TestCase{
    size_t LOG_SENDER_ITEM_NUM; 
    size_t LOG_RECEIVER_ITEM_NUM; 
    size_t SENDER_ITEM_NUM; 
    size_t RECEIVER_ITEM_NUM; 
    std::vector<block> vec_X; // sender's set
    std::vector<block> vec_Y; // receiver's set

    size_t HAMMING_WEIGHT; // cardinality of intersection
    std::vector<uint8_t> vec_indication_bit; // X[i] = Y[i] iff b[i] = 1 

    std::vector<block> vec_intersection; // for PSI 

};

// LEN is the cardinality of two sets
TestCase GenTestCase(size_t LOG_SENDER_ITEM_NUM, size_t LOG_RECEIVER_ITEM_NUM)
{
    TestCase testcase;

    testcase.LOG_SENDER_ITEM_NUM = LOG_SENDER_ITEM_NUM; 
    testcase.LOG_RECEIVER_ITEM_NUM = LOG_RECEIVER_ITEM_NUM; 
    testcase.SENDER_ITEM_NUM = size_t(pow(2, testcase.LOG_SENDER_ITEM_NUM));  
    testcase.RECEIVER_ITEM_NUM = size_t(pow(2, testcase.LOG_RECEIVER_ITEM_NUM)); 

    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.SENDER_ITEM_NUM);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.RECEIVER_ITEM_NUM);

    // set the Hamming weight to be a half of the max possible intersection size
    testcase.HAMMING_WEIGHT = std::min(testcase.SENDER_ITEM_NUM, testcase.RECEIVER_ITEM_NUM)/2;

    // generate a random indication bit vector conditioned on given Hamming weight
    testcase.vec_indication_bit.resize(testcase.SENDER_ITEM_NUM);  
    for(auto i = 0; i < testcase.SENDER_ITEM_NUM; i++){
        if(i < testcase.HAMMING_WEIGHT) testcase.vec_indication_bit[i] = 1; 
        else testcase.vec_indication_bit[i] = 0; 
    }
    std::shuffle(testcase.vec_indication_bit.begin(), testcase.vec_indication_bit.end(), global_built_in_prg);

    // adjust vec_X and vec_Y
    for(auto i = 0, j = 0; i < testcase.SENDER_ITEM_NUM; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_X[i] = testcase.vec_Y[j];
            testcase.vec_intersection.emplace_back(testcase.vec_Y[j]); 
            j++; 
        }
    }

    std::shuffle(testcase.vec_Y.begin(), testcase.vec_Y.end(), global_built_in_prg);

    return testcase; 
}

void PrintTestCase(TestCase testcase)
{
    PrintSplitLine('-'); 
    std::cout << "TESTCASE INFO >>>" << std::endl;
    std::cout << "Sender's set size = " << testcase.SENDER_ITEM_NUM << std::endl;
    std::cout << "Receiver's set size = " << testcase.RECEIVER_ITEM_NUM << std::endl;
    std::cout << "Intersection cardinality = " << testcase.HAMMING_WEIGHT << std::endl; 
    PrintSplitLine('-'); 
}

void SaveTestCase(TestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }

    fout << testcase.LOG_SENDER_ITEM_NUM; 
    fout << testcase.LOG_RECEIVER_ITEM_NUM; 
    fout << testcase.SENDER_ITEM_NUM; 
    fout << testcase.RECEIVER_ITEM_NUM; 
    fout << testcase.HAMMING_WEIGHT; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_indication_bit;
    fout << testcase.vec_intersection; 

    fout.close(); 
}

void FetchTestCase(TestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }

    fin >> testcase.LOG_SENDER_ITEM_NUM; 
    fin >> testcase.LOG_RECEIVER_ITEM_NUM; 
    fin >> testcase.SENDER_ITEM_NUM; 
    fin >> testcase.RECEIVER_ITEM_NUM;
    fin >> testcase.HAMMING_WEIGHT; 

    testcase.vec_X.resize(testcase.SENDER_ITEM_NUM); 
    testcase.vec_Y.resize(testcase.RECEIVER_ITEM_NUM); 
    testcase.vec_indication_bit.resize(testcase.SENDER_ITEM_NUM); 
    testcase.vec_intersection.resize(testcase.HAMMING_WEIGHT);   

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_indication_bit;
    fin >> testcase.vec_intersection; 

    fin.close(); 
}

int main()
{
    CRYPTO_Initialize(); 

    std::cout << "mqRPMT-based PSI test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "mqRPMTPSI.pp"; 
    mqRPMTPSI::PP pp;   
    if(!FileExist(pp_filename)){
        std::cout << pp_filename << " does not exist" << std::endl; 
        size_t computational_security_parameter = 128;         
        size_t statistical_security_parameter = 40; 
        size_t LOG_SENDER_ITEM_NUM = 20;
        size_t LOG_RECEIVER_ITEM_NUM = 20;  
        pp = mqRPMTPSI::Setup(computational_security_parameter, statistical_security_parameter, LOG_SENDER_ITEM_NUM, LOG_RECEIVER_ITEM_NUM); 
        mqRPMTPSI::SavePP(pp, pp_filename); 
    }
    else{
        std::cout << pp_filename << " already exists" << std::endl; 
        mqRPMTPSI::FetchPP(pp, pp_filename); 
    }

    std::string testcase_filename = "mqRPMTPSI.testcase"; 
    
    // generate test instance (must be same for server and client)
    TestCase testcase; 
    if(!FileExist(testcase_filename)){ 
        std::cout << testcase_filename << " does not exist" << std::endl; 
        testcase = GenTestCase(pp.LOG_SENDER_ITEM_NUM, pp.LOG_RECEIVER_ITEM_NUM); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        std::cout << testcase_filename << " already exist" << std::endl; 
        FetchTestCase(testcase, testcase_filename);
        if((testcase.LOG_SENDER_ITEM_NUM != pp.LOG_SENDER_ITEM_NUM) || (testcase.LOG_SENDER_ITEM_NUM != pp.LOG_SENDER_ITEM_NUM)){
            std::cerr << "testcase and public parameter do not match" << std::endl; 
        }
    }
    PrintTestCase(testcase); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: first start receiver, then start sender) ==> "; 

    std::getline(std::cin, party);
    PrintSplitLine('-'); 

    if(party == "sender"){
        NetIO client("client", "127.0.0.1", 8080);        
        mqRPMTPSI::Send(client, pp, testcase.vec_X);
    } 

    if(party == "receiver"){
        NetIO server("server", "", 8080);
        std::vector<block> vec_intersection_real = mqRPMTPSI::Receive(server, pp, testcase.vec_Y); // real result
        std::set<block, BlockCompare> set_diff_result = 
            ComputeSetDifference(vec_intersection_real, testcase.vec_intersection);  

        double error_probability = set_diff_result.size()/double(testcase.vec_intersection.size()); 
        std::cout << "mqRPMT-based PSI test succeeds with probability " << (1 - error_probability) << std::endl; 
    }

    CRYPTO_Finalize();   
    
    return 0; 
}