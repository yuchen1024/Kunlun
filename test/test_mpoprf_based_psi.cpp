#include "../mpc/psi/psi_from_oprf.hpp"
#include "../crypto/setup.hpp"

std::set<block, BlockCompare> ComputeSetDifference(std::vector<block> &vec_A, std::vector<block> &vec_B)
{ 
    std::cout << vec_A.size() << vec_B.size() << std::endl;
    std::set<block, BlockCompare> set_A;
    for(auto var: vec_A) set_A.insert(var); 

    std::set<block, BlockCompare> set_B;
    for(auto var: vec_B) set_B.insert(var); 

    BlockCompare blockcmp; 
    std::set<block, BlockCompare> set_diff_result;  
    std::set_difference(set_A.begin(), set_A.end(), set_B.begin(), set_B.end(), 
                        std::inserter<std::set<block, BlockCompare>>(set_diff_result, set_diff_result.end()), 
                        blockcmp);
    
    return set_diff_result; 
}

struct MPOPRFPSITestCase{
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    std::vector<uint8_t> vec_indication_bit; // X[i] = Y[i] iff b[i] = 1 
    std::vector<block> vec_intersection; // for PSI 
    size_t CARDINALITY; // for cardinality
    size_t LEN; // size of set 
};

MPOPRFPSITestCase GenTestCase(size_t log_set_size)
{
    MPOPRFPSITestCase testcase;
    testcase.LEN = 1 << log_set_size; 

    PRG::Seed seed = PRG::SetSeed(fix_key, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.LEN);
    testcase.vec_indication_bit = PRG::GenRandomBits(seed, testcase.LEN); 

    testcase.CARDINALITY = 0; 
    for(auto i = 0; i < testcase.LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.CARDINALITY++;
            testcase.vec_Y[i] = testcase.vec_X[i]; 
            testcase.vec_intersection.emplace_back(testcase.vec_Y[i]); 
        }
    } 
    std::cout << "intersection cardinality = " << testcase.CARDINALITY << std::endl; 

    return testcase; 
}

void SaveTestCase(MPOPRFPSITestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << testcase.LEN; 
    fout << testcase.CARDINALITY; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_indication_bit;
    fout << testcase.vec_intersection; 

    fout.close(); 
}

void FetchTestCase(MPOPRFPSITestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> testcase.LEN; 
    fin >> testcase.CARDINALITY; 

    testcase.vec_X.resize(testcase.LEN); 
    testcase.vec_Y.resize(testcase.LEN); 
    testcase.vec_indication_bit.resize(testcase.LEN); 
    testcase.vec_intersection.resize(testcase.CARDINALITY);   

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_indication_bit;
    fin >> testcase.vec_intersection; 

    fin.close(); 
}

int main()
{
	Global_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    std::cout << "mpoprf-based PSI test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    size_t log_set_size = 20;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "MPOPRF.pp"; 
    MPOPRF::PP pp; 
    if(!FileExist(pp_filename)){
        pp = MPOPRF::Setup(log_set_size); // 40 is the statistical parameter
        MPOPRF::SavePP(pp, pp_filename); 
    }
    else{
        MPOPRF::FetchPP(pp, pp_filename); 
    }

    std::cout << "number of elements = " << (1 << log_set_size) << std::endl; 

    std::string testcase_filename = "MPOPRFPSI.testcase"; 
    
    MPOPRFPSITestCase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestCase(log_set_size); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between server and receiver (hint: start sender first) ==> ";  
    std::getline(std::cin, party); 

    /* size_t log_set_size = 20;
    MPOPRF::PP pp = MPOPRF::Setup(log_set_size); 
    MPOPRFPSITestCase testcase = GenTestCase(log_set_size); */

	if (party == "sender")
	{
        NetIO server("server", "", 8080);
        OPRFPSI::Send(server, pp, testcase.vec_X, pp.set_size);
    }
    
    if (party == "receiver")
	{
        NetIO client("client", "127.0.0.1", 8080);
        std::vector<uint8_t> vec_indication_bit_prime = OPRFPSI::Receive(client, pp, testcase.vec_Y, pp.set_size);

        if(CompareBits(testcase.vec_indication_bit, vec_indication_bit_prime))
            std::cout << "PSI test succeeds" << std::endl; 
        else
            std::cout << "PSI test fails" << std::endl;
	}

	ECGroup_Finalize(); 
    Global_Finalize();  
	return 0; 
}