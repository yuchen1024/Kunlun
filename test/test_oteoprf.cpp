#include "../mpc/oprf/ote_oprf.hpp"
#include "../crypto/setup.hpp"

struct OTEOPRFTestCase{
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    size_t LEN; // size of set 
};

OTEOPRFTestCase GenTestCase(size_t LOG_LEN)
{
    OTEOPRFTestCase testcase;
    testcase.LEN = 1 << LOG_LEN; 

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.LEN);

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
    fout << testcase.LEN; 
     
    fout << testcase.vec_X; 

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
    fin >> testcase.LEN; 

    testcase.vec_X.resize(testcase.LEN); 

    fin >> testcase.vec_X; 

    fin.close(); 
}

int main()
{
	CRYPTO_Initialize(); 

    std::cout << "OTE-based OPRF test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    size_t LOG_LEN = 20;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "OTEOPRF.pp"; 
    OTEOPRF::PP pp; 
    if(!FileExist(pp_filename)){
        pp = OTEOPRF::Setup(LOG_LEN); // 40 is the statistical parameter
        OTEOPRF::SavePP(pp, pp_filename); 
    }
    else{
        OTEOPRF::FetchPP(pp, pp_filename); 
    }

    std::cout << "number of elements = " << (1 << LOG_LEN) << std::endl; 

    std::string testcase_filename = "OTEOPRF.testcase"; 
    
    OTEOPRFTestCase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestCase(LOG_LEN); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between server and receiver (hint: first start server, then start client) ==> ";  
    std::getline(std::cin, party); 


	if (party == "server")
	{
        NetIO server_io("server", "", 8080);

        std::vector<std::vector<uint8_t>> oprf_key = OTEOPRF::Server(server_io, pp);
        std::vector<std::vector<uint8_t>> vec_Fk_X = OTEOPRF::Evaluate(pp, oprf_key, testcase.vec_X, pp.LEN);        
    }
    
    if (party == "client")
	{
        NetIO client_io("client", "127.0.0.1", 8080);
        std::vector<std::vector<uint8_t>> vec_Fk_X = OTEOPRF::Client(client_io, pp, testcase.vec_X, pp.LEN);
	}

    CRYPTO_Finalize();

	return 0; 
}