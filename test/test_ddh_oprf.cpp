#include "../mpc/oprf/ddh_oprf.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/setup.hpp"

struct DDHOPRFTestCase{
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    size_t INPUT_NUM; // size of set 
    std::vector<uint64_t> permutation_map; // permutation
};

DDHOPRFTestCase GenTestCase(size_t LOG_INPUT_NUM)
{
    DDHOPRFTestCase testcase;
    testcase.INPUT_NUM = 1 << LOG_INPUT_NUM; 

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.INPUT_NUM);
    testcase.vec_Y = testcase.vec_X; 

    testcase.permutation_map.resize(testcase.INPUT_NUM); 
    for(auto i = 0; i < testcase.INPUT_NUM; i++){
        testcase.permutation_map[i] = i; 
    }
    return testcase; 
}

void SaveTestCase(DDHOPRFTestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << testcase.INPUT_NUM; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.permutation_map; 

    fout.close(); 
}

void FetchTestCase(DDHOPRFTestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> testcase.INPUT_NUM; 

    testcase.vec_X.resize(testcase.INPUT_NUM); 
    fin >> testcase.vec_X; 

    testcase.vec_Y.resize(testcase.INPUT_NUM); 
    fin >> testcase.vec_Y; 

    testcase.permutation_map.resize(testcase.INPUT_NUM); 
    fin >> testcase.permutation_map; 

    fin.close(); 
}

int main()
{
	CRYPTO_Initialize(); 

    std::cout << "DDH-based OPRF test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    size_t LOG_INPUT_NUM = 20;
    size_t STATISTICAL_SECURITY_PARAMETER = 40; 

    // generate pp (must be same for both server and client)
    std::string pp_filename = "DDHOPRF.pp"; 
    DDHOPRF::PP pp; 
    if(!FileExist(pp_filename)){
        pp = DDHOPRF::Setup(); 
        DDHOPRF::SavePP(pp, pp_filename); 
    }
    else{
        DDHOPRF::FetchPP(pp, pp_filename); 
    }

    std::cout << "number of input elements = " << (1 << LOG_INPUT_NUM) << std::endl; 

    std::string testcase_filename = "DDHOPRF.testcase"; 
    
    DDHOPRFTestCase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestCase(LOG_INPUT_NUM); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between server and client (hint: first start server, then start client) ==> ";  
    std::getline(std::cin, party); 


	if (party == "server")
	{
        NetIO server_io("server", "", 8080);

        std::vector<uint8_t> key = DDHOPRF::Server(server_io, pp, testcase.permutation_map, testcase.INPUT_NUM);
        std::vector<std::vector<uint8_t>> vec_Fk_X = DDHOPRF::Evaluate(pp, key, testcase.vec_X, testcase.INPUT_NUM);  
        std::vector<std::vector<uint8_t>> vec_Fk_Y;  
        server_io.ReceiveBytesVector(vec_Fk_Y);
        for(auto i = 0; i < testcase.INPUT_NUM; i++){
            for(auto j = 0; j < pp.RANGE_SIZE; j++){
                if(vec_Fk_X[i][j] != vec_Fk_Y[i][j]){
                    std::cout << "DDH-based OPRF test fails" << std::endl;
                    exit(1);
                }
            }
        }
        std::cout << "DDH-based (permuted)-OPRF test succeeds" << std::endl;
    }
    
    if (party == "client")
	{
        NetIO client_io("client", "127.0.0.1", 8080);
        std::vector<std::vector<uint8_t>> vec_Fk_Y = DDHOPRF::Client(client_io, pp, testcase.vec_Y, testcase.INPUT_NUM);
        client_io.SendBytesVector(vec_Fk_Y); 
	}

    CRYPTO_Finalize();

	return 0; 
}