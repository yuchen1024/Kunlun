#include "../mpc/vole/vole.hpp"

struct VOLETestcase{
    uint64_t N_item; // the item num of VOLE output
    // uint64_t t;    
    std::vector<block> vec_B;
    block delta; 
}; 

VOLETestcase GenTestCase(uint64_t N_item)
{	
    VOLETestcase testcase; 
    testcase.N_item = N_item; 
    // testcase.t = 397;
    
    return testcase;
}

void SaveTestCase(VOLETestcase &testcase, std::string testcase_filename)
{
    std::ofstream fout;
    fout.open(testcase_filename, std::ios::binary);
    if (!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1);
    }
    fout << testcase.N_item;
    // fout << testcase.t;
    fout << testcase.delta;
    fout << testcase.vec_B;
    fout.close();
}

void FetchTestCase(VOLETestcase &testcase, std::string testcase_filename)
{
    std::ifstream fin;
    fin.open(testcase_filename, std::ios::binary);
    if (!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1);
    }
    fin >> testcase.N_item;
    // fin >> testcase.t;
    fin >> testcase.delta;
    testcase.vec_B.resize(testcase.N_item);
    fin >> testcase.vec_B;
    fin.close();
}


int main()
{
    
	CRYPTO_Initialize(); 

	PrintSplitLine('-'); 
    std::cout << "VOLE test begins >>>" << std::endl; 
    PrintSplitLine('-'); 
 
    // set instance size
    uint64_t N_item = uint64_t(pow(2, 20)); 
    uint64_t t = 397;
    
    
    std::string testcase_filename = "vole.testcase"; 
    std::string party;
    std::cout << "please select your role between server and receiver (hint: first start server, then start client) ==> ";
    std::getline(std::cin, party);

   
    if (party == "server")
    {
        NetIO server_io("server", "", 8080);
        
        // generate vec_A, vec_C
        std::vector<block> vec_A;
        std::vector<block> vec_C;
        auto start1 = std::chrono::steady_clock::now();
        vec_A = VOLE::VOLE_A(server_io, N_item, vec_C, t);
        auto end1 = std::chrono::steady_clock::now();
        
        // get delta and vec_B from testcase
        VOLETestcase testcase; 
        FetchTestCase(testcase, testcase_filename);
	block delta = testcase.delta;
        std::vector<block> vec_B = testcase.vec_B;
 	std::cout << "Item_num = " << N_item << std::endl; 
 	std::cout << "VOLE takes A"
             << ":" << std::chrono::duration<double, std::milli>(end1 - start1).count() << " ms" << std::endl;  
 	
 	
 	// calculate vec_C + vec_A*delta
        for (auto i = 0; i < N_item; ++i)
        {
        	vec_C[i] ^= VOLE::gf128_mul(delta,vec_A[i]);
        }
        
        // test if vec_B == vec_C + vec_A*delta
        if(Block::Compare(vec_B,vec_C)==true){
        	PrintSplitLine('-');
        	std::cout << "VOLE test succeeds" << std::endl; 
        }
        else
        {
        	PrintSplitLine('-');
        	std::cout << "VOLE test fails" << std::endl; 
        }
       
    }

    if (party == "client")
    {
        NetIO client_io("client", "127.0.0.1", 8080);
        
        // generate delta and vec_B
        std::vector<block> vec_B;
        PRG::Seed seed = PRG::SetSeed();
        block delta = PRG::GenRandomBlocks(seed, 1)[0];
        auto start1 = std::chrono::steady_clock::now();
        VOLE::VOLE_B(client_io ,N_item ,vec_B, delta, t);
        auto end1 = std::chrono::steady_clock::now();
        std::cout << "Item_num = " << N_item << std::endl; 
        std::cout << "VOLE takes B"
            << ":" << std::chrono::duration<double, std::milli>(end1 - start1).count() << " ms" << std::endl;
        
        // save testcase for test
        VOLETestcase testcase; 
        testcase = GenTestCase(N_item); 
        testcase.delta = delta;
        testcase.vec_B = vec_B;
        SaveTestCase(testcase, testcase_filename);
    }

    PrintSplitLine('-'); 
    std::cout << "VOLE test ends >>>" << std::endl; 
    PrintSplitLine('-'); 
    
     CRYPTO_Finalize();       
	return 0; 
}
