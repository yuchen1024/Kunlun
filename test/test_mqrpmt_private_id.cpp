#include "../mpc/pso/mqrpmt_private_id.hpp"
#include "../crypto/setup.hpp"

struct TestCase{
    size_t LOG_SENDER_LEN; 
    size_t LOG_RECEIVER_LEN; 
    size_t SENDER_LEN; 
    size_t RECEIVER_LEN; 

    size_t HAMMING_WEIGHT; // cardinality of intersection
    size_t UNION_CARDINALITY; 
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    std::vector<uint8_t> vec_indication_bit; 
};

TestCase GenTestCase(size_t LOG_SENDER_LEN, size_t LOG_RECEIVER_LEN)
{
    TestCase testcase;

    testcase.LOG_SENDER_LEN = LOG_SENDER_LEN; 
    testcase.LOG_RECEIVER_LEN = LOG_RECEIVER_LEN; 
    testcase.SENDER_LEN = size_t(pow(2, testcase.LOG_SENDER_LEN));  
    testcase.RECEIVER_LEN = size_t(pow(2, testcase.LOG_RECEIVER_LEN)); 

    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.SENDER_LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.RECEIVER_LEN);

    // set the Hamming weight to be a half of the max possible intersection size
    testcase.HAMMING_WEIGHT = std::min(testcase.SENDER_LEN, testcase.RECEIVER_LEN)/2;
    testcase.UNION_CARDINALITY = testcase.SENDER_LEN + testcase.RECEIVER_LEN - testcase.HAMMING_WEIGHT; 

    // generate a random indication bit vector conditioned on given Hamming weight
    testcase.vec_indication_bit.resize(testcase.SENDER_LEN);  
    for(auto i = 0; i < testcase.SENDER_LEN; i++){
        if(i < testcase.HAMMING_WEIGHT) testcase.vec_indication_bit[i] = 1; 
        else testcase.vec_indication_bit[i] = 0; 
    }
    std::random_shuffle(testcase.vec_indication_bit.begin(), testcase.vec_indication_bit.end());

    // adjust vec_X and vec_Y
    for(auto i = 0, j = 0; i < testcase.SENDER_LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_X[i] = testcase.vec_Y[j];
            j++; 
        }
    }
    std::random_shuffle(testcase.vec_Y.begin(), testcase.vec_Y.end()); 

    return testcase; 
}

void PrintTestCase(TestCase testcase)
{
    PrintSplitLine('-'); 
    std::cout << "TESTCASE INFO >>>" << std::endl;
    std::cout << "Sender's set size = " << testcase.SENDER_LEN << std::endl;
    std::cout << "Receiver's set size = " << testcase.RECEIVER_LEN << std::endl;
    std::cout << "Union cardinality = " << testcase.UNION_CARDINALITY << std::endl; 
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
    fout << testcase.LOG_SENDER_LEN; 
    fout << testcase.LOG_RECEIVER_LEN; 
    fout << testcase.SENDER_LEN; 
    fout << testcase.RECEIVER_LEN; 
    fout << testcase.HAMMING_WEIGHT; 
    fout << testcase.UNION_CARDINALITY; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_indication_bit;

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

    fin >> testcase.LOG_SENDER_LEN; 
    fin >> testcase.LOG_RECEIVER_LEN; 
    fin >> testcase.SENDER_LEN; 
    fin >> testcase.RECEIVER_LEN;
    fin >> testcase.HAMMING_WEIGHT; 
    fin >> testcase.UNION_CARDINALITY; 

    testcase.vec_X.resize(testcase.SENDER_LEN); 
    testcase.vec_Y.resize(testcase.RECEIVER_LEN); 
    testcase.vec_indication_bit.resize(testcase.SENDER_LEN);   

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_indication_bit;

    fin.close(); 
}

int main()
{
    CRYPTO_Initialize(); 

    std::cout << "Private-ID test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "PrivateID.pp"; 
    mqRPMTPrivateID::PP pp; 
 
    if(!FileExist(pp_filename)){
        std::cout << pp_filename << " does not exist" << std::endl;
        std::string filter_type = "bloom"; 
        size_t computational_security_parameter = 128;         
        size_t statistical_security_parameter = 40; 
        size_t LOG_SENDER_LEN = 20;
        size_t LOG_RECEIVER_LEN = 20;  
        size_t LOG_INPUT_LEN = std::max(LOG_RECEIVER_LEN, LOG_SENDER_LEN); // set OPRF input length
        pp = mqRPMTPrivateID::Setup(LOG_INPUT_LEN, "bloom", 
                              computational_security_parameter, statistical_security_parameter, 
                              LOG_SENDER_LEN, LOG_RECEIVER_LEN); 
        mqRPMTPrivateID::SavePP(pp, pp_filename); 
    }
    else{
        std::cout << pp_filename << " already exists" << std::endl;
        mqRPMTPrivateID::FetchPP(pp, pp_filename); 
    }

    std::string testcase_filename = "PrivateID.testcase"; 
    
    // generate test instance (must be same for server and client)
    TestCase testcase; 
    if(!FileExist(testcase_filename)){
        std::cout << testcase_filename << " does not exist" << std::endl;
        testcase = GenTestCase(pp.LOG_SENDER_LEN, pp.LOG_RECEIVER_LEN); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        std::cout << testcase_filename << " already exists" << std::endl;
        FetchTestCase(testcase, testcase_filename);
        if((testcase.LOG_SENDER_LEN != pp.LOG_SENDER_LEN) || (testcase.LOG_SENDER_LEN != pp.LOG_SENDER_LEN)){
            std::cerr << "testcase and public parameter do not match" << std::endl; 
        }
    }
    PrintTestCase(testcase); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: first start sender, then start receiver) ==> ";  
    std::getline(std::cin, party); // first the server, then the client
    PrintSplitLine('-'); 

    size_t ITEM_LEN = pp.oprf_part.OUTPUT_LEN; // byte length of each item
    
    if(party == "sender"){
        NetIO server_io("server", "", 8080);
        mqRPMTPrivateID::Send(server_io, pp, testcase.vec_X, ITEM_LEN);
    }
    
    if(party == "receiver"){
        NetIO client_io("client", "127.0.0.1", 8080);        
        mqRPMTPrivateID::Receive(client_io, pp, testcase.vec_Y, ITEM_LEN);
    } 

    CRYPTO_Finalize();   
    
    return 0; 
}
