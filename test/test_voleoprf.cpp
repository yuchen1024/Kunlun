#include "../mpc/oprf/vole_oprf.hpp"
#include "../crypto/setup.hpp"

struct VOLEOPRFTestCase
{
    std::vector<block> vec_Y; // client set
    std::vector<block> vec_Fk_Y; 
    size_t LEN;               // size of set
};

VOLEOPRFTestCase GenTestCase(size_t LOG_LEN)
{
    VOLEOPRFTestCase testcase;
    testcase.LEN = 1 << LOG_LEN;

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.LEN);

    return testcase;
}
/*
void SaveTestCase(VOLEOPRFTestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout;
    fout.open(testcase_filename, std::ios::binary);
    if (!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1);
    }
    fout << testcase.LEN;
    fout << testcase.vec_Y;
    fout << testcase.vec_Fk_Y;

    fout.close();
}

void FetchTestCase(VOLEOPRFTestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin;
    fin.open(testcase_filename, std::ios::binary);
    if (!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1);
    }
    fin >> testcase.LEN;
   // testcase.vec_Y.resize(testcase.LEN);
    fin >> testcase.vec_Y;
    //testcase.vec_Fk_Y.resize(testcase.LEN);
    fin >> testcase.vec_Fk_Y;
	
    fin.close();
}
*/
int main()
{
    CRYPTO_Initialize();

    std::cout << "VOLE-based OPRF test begins >>>" << std::endl;

    PrintSplitLine('-');
    // std::cout << "generate or load public parameters and test case" << std::endl;

    size_t LOG_LEN = 20;

    VOLEOPRF::PP pp;

    pp = VOLEOPRF::Setup(LOG_LEN); // 40 is the statistical parameter

    std::cout << "number of elements = " << (1 << LOG_LEN) << std::endl;

    std::string testcase_filename = "VOLEOPRF.testcase";

    VOLEOPRFTestCase testcase;
    testcase = GenTestCase(LOG_LEN);

    std::string party;
    std::cout << "please select your role between server and receiver (hint: first start server, then start client) ==> ";
    std::getline(std::cin, party);

    if (party == "server")
    {
        
        NetIO server_io("server", "", 8080);
        
        auto start_time = std::chrono::steady_clock::now(); 
        std::vector<block> oprf_key = VOLEOPRF::Server1(server_io, pp);
        std::vector<block> vec_Fk_X = VOLEOPRF::Evaluate1(pp, oprf_key, testcase.vec_Y, pp.LEN);
        auto end_time = std::chrono::steady_clock::now();
        
        server_io.SendBlocks(vec_Fk_X.data(), pp.LEN);
        
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF: Server side takes time "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms" << std::endl;
        PrintSplitLine('-');          

    }

    if (party == "client")
    {
        NetIO client_io("client", "127.0.0.1", 8080);
        
        PrintSplitLine('-'); 
        
        auto start_time = std::chrono::steady_clock::now();   
        std::vector<block> vec_Fk_Y = VOLEOPRF::Client1(client_io, pp, testcase.vec_Y, pp.LEN);
	auto end_time = std::chrono::steady_clock::now();
        
        // receive vec_Fk_X from sender/server
        std::vector<block> vec_Fk_X(pp.LEN);
        client_io.ReceiveBlocks(vec_Fk_X.data(), pp.LEN);
        
        if(Block::Compare(vec_Fk_Y,vec_Fk_X)==true){
        	PrintSplitLine('-');
        	std::cout << "VOLEOPRF test succeeds" << std::endl; 
        }
        else
        {
        	PrintSplitLine('-');
        	std::cout << "VOLEOPRF test fails" << std::endl; 
        }   
         
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF: Client side takes time "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms" << std::endl;
        PrintSplitLine('-');        

    }

    CRYPTO_Finalize();

    return 0;
}
