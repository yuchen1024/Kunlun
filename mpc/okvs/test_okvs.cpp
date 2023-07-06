#include "./Baxos.hpp"
#include "./Paxos.hpp"
#include "../crypto/setup.hpp"

struct OKVSTestcase{
    size_t ITEM_NUM; 
    size_t BIN_SIZE;
    size_t thread_num;
    PRG::Seed seed;
    std::vector<block> vec_value; 
    std::vector<block> vec_key; 
    
}; 

OKVSTestcase GenTestCase(size_t ITEM_NUM)
{	
    OKVSTestcase testcase; 
    testcase.ITEM_NUM = ITEM_NUM; 
    testcase.BIN_SIZE = size_t(pow(2, 15));
    testcase.thread_num = 4; 
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); 
    testcase.vec_value = PRG::GenRandomBlocks(seed, ITEM_NUM);
    testcase.vec_key = PRG::GenRandomBlocks(seed, ITEM_NUM);

    return testcase;
}

void SaveTestCase(OKVSTestcase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << testcase.ITEM_NUM; 
    fout << testcase.BIN_SIZE; 
    fout << testcase.thread_num; 

    fout << testcase.vec_value; 
    fout << testcase.vec_key; 

    fout.close(); 
}

void FetchTestCase(OKVSTestcase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> testcase.ITEM_NUM; 
    fin >> testcase.BIN_SIZE; 
    fin >> testcase.thread_num; 
	testcase.vec_value.resize(testcase.ITEM_NUM); 
	testcase.vec_key.resize(testcase.ITEM_NUM); 
    fin >> testcase.vec_value; 
    fin >> testcase.vec_key; 

    fin.close(); 
}

int main()
{
    
	CRYPTO_Initialize(); 

	PrintSplitLine('-'); 
    std::cout << "OKVS test begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "generate or load public parameters and test case" << std::endl;

    // set instance size
    size_t ITEM_NUM = size_t(pow(2, 20)); 
    std::cout << "ITEM_NUM of OKVS = " << ITEM_NUM << std::endl; 

    // generate or fetch test case
    std::string testcase_filename = "okvs.testcase"; 
    OKVSTestcase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestCase(ITEM_NUM); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
	PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); 
    Baxos<gf_128> baxos(testcase.ITEM_NUM, testcase.BIN_SIZE, 3);
    std::vector<block> encode_result(baxos.bin_num * baxos.total_size);
    std::vector<block> decode_result(testcase.ITEM_NUM);
    baxos.solve(testcase.vec_key, testcase.vec_value, encode_result, &seed, testcase.thread_num);

    baxos.decode(testcase.vec_key, decode_result, encode_result, testcase.thread_num);

    for (auto i = 0; i < testcase.vec_value.size(); i++)
    {
        if (!Block::Compare(decode_result[i], testcase.vec_value[i]))
        {
            std::cout << "OKVS test fails" << std::endl; 
        }
    }

    std::cout << "OKVS test succeeds" << std::endl; 


    PrintSplitLine('-'); 
    std::cout << "OKVS test ends >>>" << std::endl; 
    PrintSplitLine('-'); 

    CRYPTO_Finalize();   
	return 0; 
}
