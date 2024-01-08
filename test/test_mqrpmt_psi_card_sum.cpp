#include "../mpc/pso/mqrpmt_psi_card_sum.hpp"
#include "../crypto/setup.hpp"


struct TestCase{
    size_t LOG_SENDER_ITEM_NUM; 
    size_t LOG_RECEIVER_ITEM_NUM; 
    size_t SENDER_ITEM_NUM; 
    size_t RECEIVER_ITEM_NUM; 

    size_t HAMMING_WEIGHT; 

    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    std::vector<BigInt> vec_value; // vec_Y's value
    std::vector<uint8_t> vec_indication_bit; // X[i] = Y[i] iff b[i] = 1 

    BigInt INTERSECTION_SUM;  // for PSI-sum: the sum of intersection labels
    size_t LOG_VALUE_BOUND; 
    size_t LOG_SUM_BOUND; // binary length of SUM_BOUND
    BigInt VALUE_BOUND; 
    BigInt SUM_BOUND; 
};

// LEN is the cardinality of two sets
TestCase GenTestCase(size_t LOG_SENDER_ITEM_NUM, size_t LOG_RECEIVER_ITEM_NUM, 
                     size_t LOG_VALUE_BOUND, size_t LOG_SUM_BOUND)
{
    TestCase testcase;
    testcase.LOG_SENDER_ITEM_NUM = LOG_SENDER_ITEM_NUM; 
    testcase.LOG_RECEIVER_ITEM_NUM = LOG_RECEIVER_ITEM_NUM; 
    testcase.SENDER_ITEM_NUM = size_t(pow(2, testcase.LOG_SENDER_ITEM_NUM)); 
    testcase.RECEIVER_ITEM_NUM = size_t(pow(2, testcase.LOG_RECEIVER_ITEM_NUM)); 

    testcase.LOG_VALUE_BOUND = LOG_VALUE_BOUND; 
    testcase.LOG_SUM_BOUND = LOG_SUM_BOUND; 
    testcase.VALUE_BOUND = size_t(pow(2, testcase.LOG_VALUE_BOUND)); 
    testcase.SUM_BOUND = size_t(pow(2, testcase.LOG_SUM_BOUND)); 
    

    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.SENDER_ITEM_NUM);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.RECEIVER_ITEM_NUM);
    testcase.vec_indication_bit = PRG::GenRandomBits(seed, testcase.SENDER_ITEM_NUM); 

    // set the Hamming weight to be a half of the max possible intersection size
    testcase.HAMMING_WEIGHT = std::min(testcase.SENDER_ITEM_NUM, testcase.RECEIVER_ITEM_NUM)/2;

    // generate a random indication bit vector conditioned on given Hamming weight
    testcase.vec_indication_bit.resize(testcase.SENDER_ITEM_NUM);  
    for(auto i = 0; i < testcase.SENDER_ITEM_NUM; i++){
        if(i < testcase.HAMMING_WEIGHT) testcase.vec_indication_bit[i] = 1; 
        else testcase.vec_indication_bit[i] = 0; 
    }

    std::shuffle(testcase.vec_indication_bit.begin(), testcase.vec_indication_bit.end(), global_built_in_prg);

    testcase.vec_value = GenRandomBigIntVectorLessThan(testcase.SENDER_ITEM_NUM, testcase.VALUE_BOUND); 
    testcase.INTERSECTION_SUM = bn_0; 
    
    // adjust vec_X and vec_Y
    for(auto i = 0, j = 0; i < testcase.SENDER_ITEM_NUM; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_X[i] = testcase.vec_Y[j];
            j++; 
            testcase.INTERSECTION_SUM += testcase.vec_value[i]; 
        }
    }
    testcase.INTERSECTION_SUM = testcase.INTERSECTION_SUM % testcase.SUM_BOUND; 

    std::shuffle(testcase.vec_Y.begin(), testcase.vec_Y.end(), global_built_in_prg);

    return testcase; 
}

void PrintTestCase(TestCase testcase)
{
    PrintSplitLine('-'); 
    std::cout << "TESTCASE INFO >>>" << std::endl;
    std::cout << "Sender's set size = " << testcase.SENDER_ITEM_NUM << std::endl;
    std::cout << "Receiver's set size = " << testcase.RECEIVER_ITEM_NUM << std::endl;
    testcase.VALUE_BOUND.PrintInDec("Value bound"); 
    testcase.SUM_BOUND.PrintInDec("Sum bound"); 

    std::cout << "Intersection cardinality = " << testcase.HAMMING_WEIGHT << std::endl; 
    testcase.INTERSECTION_SUM.PrintInDec("Intersection sum"); 
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

    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_value;
    fout << testcase.vec_indication_bit;

    fout << testcase.HAMMING_WEIGHT; 
    fout << testcase.INTERSECTION_SUM;  // for PSI-card-sum: the sum of intersection labels
    fout << testcase.LOG_VALUE_BOUND; 
    fout << testcase.LOG_SUM_BOUND; // binary length of SUM_BOUND

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

    testcase.vec_X.resize(testcase.SENDER_ITEM_NUM); 
    testcase.vec_Y.resize(testcase.RECEIVER_ITEM_NUM); 
    testcase.vec_value.resize(testcase.SENDER_ITEM_NUM);
    testcase.vec_indication_bit.resize(testcase.SENDER_ITEM_NUM); 

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_value;
    fin >> testcase.vec_indication_bit;

    fin >> testcase.HAMMING_WEIGHT; 
    fin >> testcase.INTERSECTION_SUM;  
    fin >> testcase.LOG_VALUE_BOUND; 
    fin >> testcase.LOG_SUM_BOUND; // binary length of SUM_BO

    fin.close(); 

    testcase.VALUE_BOUND = size_t(pow(2, testcase.LOG_VALUE_BOUND)); 
    testcase.SUM_BOUND = size_t(pow(2, testcase.LOG_SUM_BOUND)); 
}

int main()
{
    CRYPTO_Initialize(); 

    std::cout << "mqRPMT-based PSI-card-sum test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "mqRPMTPSIcardsum.pp"; 
    mqRPMTPSIcardsum::PP pp; 
    if(!FileExist(pp_filename)){
        std::cout << pp_filename << " does not exist" << std::endl;
        size_t computational_security_parameter = 128;         
        size_t statistical_security_parameter = 40; 
        size_t LOG_SENDER_ITEM_NUM = 20;
        size_t LOG_RECEIVER_ITEM_NUM = 20;  

        size_t LOG_SUM_BOUND = 32;  
        size_t LOG_VALUE_BOUND = LOG_SUM_BOUND - LOG_SENDER_ITEM_NUM; // value * sender_item_num \leq sum  

        pp = mqRPMTPSIcardsum::Setup(computational_security_parameter, statistical_security_parameter, 
                                     LOG_SENDER_ITEM_NUM, LOG_RECEIVER_ITEM_NUM, LOG_SUM_BOUND, LOG_VALUE_BOUND); 
        mqRPMTPSIcardsum::SavePP(pp, pp_filename); 
    }
    else{
        std::cout << pp_filename << " already exists" << std::endl;
        mqRPMTPSIcardsum::FetchPP(pp, pp_filename); 
    }

    std::string testcase_filename = "mqRPMTPSIcardsum.testcase"; 
    
    // generate test instance (must be same for server and client)
    TestCase testcase; 
    if(!FileExist(testcase_filename)){
        std::cout << testcase_filename << " does not exist" << std::endl;
        size_t LOG_SUM_BOUND = 32;  
        size_t LOG_VALUE_BOUND = LOG_SUM_BOUND - pp.LOG_SENDER_ITEM_NUM; 
        testcase = GenTestCase(pp.LOG_SENDER_ITEM_NUM, pp.LOG_RECEIVER_ITEM_NUM, LOG_VALUE_BOUND, LOG_SUM_BOUND); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        std::cout << testcase_filename << " already exists" << std::endl;
        FetchTestCase(testcase, testcase_filename);
        if((testcase.LOG_SENDER_ITEM_NUM != pp.LOG_SENDER_ITEM_NUM) || (testcase.LOG_SENDER_ITEM_NUM != pp.LOG_SENDER_ITEM_NUM)){
            std::cerr << "testcase and public parameter do not match" << std::endl; 
        }
    }
    PrintTestCase(testcase); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: first start sender, then start receiver) ==> ";  

    std::getline(std::cin, party);
    PrintSplitLine('-'); 

    if(party == "sender"){
        NetIO server("server", "", 8080);

        size_t CARDINALITY; 
        BigInt SUM; 

        std::tie(CARDINALITY, SUM)  = mqRPMTPSIcardsum::Send(server, pp, testcase.vec_X, testcase.vec_value); 

        std::cout << "INTERSECTION CARDINALITY = " << CARDINALITY << std::endl;
        SUM.PrintInDec("INTERSECTION SUM");

        if(CARDINALITY == testcase.HAMMING_WEIGHT && SUM == testcase.INTERSECTION_SUM){
            std::cout << "mqRPMT-based PSI-card-sum test succeeds" << std::endl; 
        }
        else{
            std::cout << "mqRPMT-based PSI-card-sum test fails" << std::endl; 
        }
    }
    
    if(party == "receiver"){
        NetIO client("client", "127.0.0.1", 8080);        

        size_t CARDINALITY = mqRPMTPSIcardsum::Receive(client, pp, testcase.vec_Y);
        std::cout << "INTERSECTION CARDINALITY (test) = " << CARDINALITY << std::endl;

        double error_probability = abs(double(testcase.HAMMING_WEIGHT)-double(CARDINALITY))/double(testcase.HAMMING_WEIGHT); 
        std::cout << "mqRPMT-based PSI-card-sum test succeeds with probability " << (1 - error_probability) << std::endl; 
 
    }

    CRYPTO_Finalize();   
    
    return 0; 
}