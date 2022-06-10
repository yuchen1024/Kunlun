#include "../mpc/pid/private_id.hpp"

struct PIDTestCase{
    std::vector<block> vec_X; // server set
    // std::vector<std::string> vec_X_id;
    std::vector<block> vec_Y; // client set
    // std::vector<std::string> vec_Y_id; 
    std::vector<uint8_t> vec_indication_bit; 
    // std::vector<std::string> vec_union_id; 

    size_t ITEM_NUM;
    size_t UNION_SIZE; 
};

PIDTestCase GenTestCase(size_t ITEM_NUM)
{
    PIDTestCase testcase;
    testcase.ITEM_NUM = ITEM_NUM;
    testcase.UNION_SIZE = ITEM_NUM;  

    PRG::Seed seed = PRG::SetSeed(PRG::fixed_salt, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, ITEM_NUM);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, ITEM_NUM);
    testcase.vec_indication_bit = PRG::GenRandomBits(seed, ITEM_NUM); 

    
    for(auto i = 0; i < ITEM_NUM; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_Y[i] = testcase.vec_X[i];
        }
        else{
            testcase.UNION_SIZE++; 
        }
    } 
    std::cout << "union size = " << testcase.UNION_SIZE << std::endl;

    return testcase; 
}

void SaveTestCase(PIDTestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << testcase.ITEM_NUM; 
    fout << testcase.UNION_SIZE; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 

    fout.close(); 
}

void FetchTestCase(PIDTestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> testcase.ITEM_NUM; 
    fin >> testcase.UNION_SIZE; 

    testcase.vec_X.resize(testcase.ITEM_NUM); 
    testcase.vec_Y.resize(testcase.ITEM_NUM); 

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 

    fin.close(); 
}

int main()
{
    CRYPTO_Initialize(); 

    std::cout << "Private-ID test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "PID.pp"; 
    PID::PP pp; 

    size_t LOG_ITEM_NUM = 8; 
    size_t ITEM_NUM = size_t(pow(2, LOG_ITEM_NUM)); 

    if(!FileExist(pp_filename)){
        pp = PID::Setup(LOG_ITEM_NUM, "bloom", 40); // 40 is the statistical parameter
        PID::SavePP(pp, pp_filename); 
    }
    else{
        PID::FetchPP(pp, pp_filename); 
    }

    //OTEOPRF::PrintPP(pp.oprf_part); 

    std::cout << "number of elements = " << ITEM_NUM << std::endl; 

    std::string testcase_filename = "PID.testcase"; 
    
    // generate test instance (must be same for server and client)
    PIDTestCase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestCase(ITEM_NUM); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: first start sender, then start receiver) ==> ";  
    std::getline(std::cin, party); // first the server, then the client
    PrintSplitLine('-'); 


    size_t ITEM_LEN = pp.oprf_part.OUTPUT_LEN; 
    if(party == "sender"){
        NetIO server_io("server", "", 8080);
        PID::Send(server_io, pp, testcase.vec_X, ITEM_LEN, ITEM_NUM);
    }
    
    if(party == "receiver"){
        NetIO client_io("client", "127.0.0.1", 8080);        
        PID::Receive(client_io, pp, testcase.vec_Y, ITEM_LEN, ITEM_NUM);
    } 

    CRYPTO_Finalize();   
    
    return 0; 
}
