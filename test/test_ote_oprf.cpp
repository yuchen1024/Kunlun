#include "../mpc/oprf/ote_oprf.hpp"
#include "../crypto/setup.hpp"

struct OTEOPRFTestCase{
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    size_t INPUT_NUM; // size of set 
};

OTEOPRFTestCase GenTestCase(size_t LOG_INPUT_NUM)
{
    OTEOPRFTestCase testcase;
    testcase.INPUT_NUM = 1 << LOG_INPUT_NUM; 

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.INPUT_NUM);
    testcase.vec_Y = testcase.vec_X; 

    return testcase; 
}

void SaveTestCase(OTEOPRFTestCase &testcase, std::string testcase_filename)
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

    fout.close(); 
}

void FetchTestCase(OTEOPRFTestCase &testcase, std::string testcase_filename)
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

    fin.close(); 
}

int main()
{
	CRYPTO_Initialize(); 

    std::cout << "OTE-based OPRF test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    size_t LOG_INPUT_NUM = 20;
    size_t STATISTICAL_SECURITY_PARAMETER = 40; 

    // generate pp (must be same for both server and client)
    std::string pp_filename = "OTEOPRF.pp"; 
    OTEOPRF::PP pp; 
    if(!FileExist(pp_filename)){
        pp = OTEOPRF::Setup(LOG_INPUT_NUM, STATISTICAL_SECURITY_PARAMETER); // 40 is the statistical parameter
        OTEOPRF::SavePP(pp, pp_filename); 
    }
    else{
        OTEOPRF::FetchPP(pp, pp_filename); 
    }

    std::cout << "number of input elements = " << (1 << LOG_INPUT_NUM) << std::endl; 

    std::string testcase_filename = "OTEOPRF.testcase"; 
    
    OTEOPRFTestCase testcase; 
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

        std::vector<uint8_t> key = OTEOPRF::Server(server_io, pp);
        std::vector<std::vector<uint8_t>> vec_Fk_X = OTEOPRF::Evaluate(pp, key, testcase.vec_X, pp.INPUT_NUM);  

        std::vector<std::vector<uint8_t>> vec_Fk_Y;  
        server_io.ReceiveBytesVector(vec_Fk_Y);
        for(auto i = 0; i < pp.INPUT_NUM; i++){
            for(auto j = 0; j < pp.RANGE_SIZE; j++){
                if(vec_Fk_X[i][j] != vec_Fk_Y[i][j]){
                    std::cout << "OTE-based OPRF test fails" << std::endl;
                    exit(1);
                }
            }
        }
        std::cout << "OTE-based OPRF test succeeds" << std::endl;
    }
    
    if (party == "client")
	{
        NetIO client_io("client", "127.0.0.1", 8080);
        std::vector<std::vector<uint8_t>> vec_Fk_Y = OTEOPRF::Client(client_io, pp, testcase.vec_Y, pp.INPUT_NUM);
        client_io.SendBytesVector(vec_Fk_Y); 
	}

    CRYPTO_Finalize();

	return 0; 
}