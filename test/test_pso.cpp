#include "../mpc/pso/mqrpmt_pso.hpp"

std::set<block, BlockCompare> ComputeSetDifference(std::vector<block> &vec_A, std::vector<block> &vec_B)
{ 
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

struct PSOTestCase{
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    std::vector<int64_t> vec_label; // vec_Y's label
    std::vector<uint8_t> vec_indication_bit; // X[i] = Y[i] iff b[i] = 1 
    std::vector<block> vec_intersection; // for PSI 
    std::vector<block> vec_union; // for PSU
    int64_t SUM;  // for PSI-sum: the sum of intersection labels
    size_t CARDINALITY; // for cardinality
    size_t LEN; // size of set 
};

PSOTestCase GenTestCase(size_t LEN)
{
    PSOTestCase testcase;
    testcase.LEN = LEN; 

    PRG::Seed seed = PRG::SetSeed(PRG::fixed_salt, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, LEN);
    testcase.vec_indication_bit = PRG::GenRandomBits(seed, LEN); 

    testcase.vec_label = GenRandomIntegerVectorLessThan(LEN, 100);     
  
    testcase.CARDINALITY = 0; 
    testcase.SUM = 0;
    testcase.vec_union = testcase.vec_X; 
    
    for(auto i = 0; i < LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_Y[i] = testcase.vec_X[i];
            testcase.CARDINALITY++; 
            testcase.SUM += testcase.vec_label[i];  
            testcase.vec_intersection.emplace_back(testcase.vec_Y[i]); 
        }
        else{
            testcase.vec_union.emplace_back(testcase.vec_Y[i]); 
        }
    } 
    std::cout << "intersection cardinality = " << testcase.CARDINALITY << std::endl; 
    std::cout << "intersection sum = " << testcase.SUM << std::endl;

    return testcase; 
}

void SaveTestCase(PSOTestCase &testcase, std::string testcase_filename)
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
    fout << testcase.SUM; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_label;
    fout << testcase.vec_indication_bit;
    fout << testcase.vec_intersection; 
    fout << testcase.vec_union; 

    fout.close(); 
}

void FetchTestCase(PSOTestCase &testcase, std::string testcase_filename)
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
    fin >> testcase.SUM; 

    testcase.vec_X.resize(testcase.LEN); 
    testcase.vec_Y.resize(testcase.LEN); 
    testcase.vec_label.resize(testcase.LEN);
    testcase.vec_indication_bit.resize(testcase.LEN); 
    testcase.vec_intersection.resize(testcase.CARDINALITY); 
    testcase.vec_union.resize(2*testcase.LEN - testcase.CARDINALITY);  

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_label;
    fin >> testcase.vec_indication_bit;
    fin >> testcase.vec_intersection; 
    fin >> testcase.vec_union; 

    fin.close(); 
}

int main()
{
    CRYPTO_Initialize(); 

    PSO_type current = PSI_sum; 

    switch(current) {
        case PSI: std::cout << "PSI"; break; 
        case PSU: std::cout << "PSU"; break; 
        case PSI_card: std::cout << "PSI-card"; break; 
        case PSI_sum: std::cout << "PSI-sum"; break; 
    }
    std::cout << " test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "PSO.pp"; 
    PSO::PP pp; 
    if(!FileExist(pp_filename)){
        pp = PSO::Setup("bloom", 40); // 40 is the statistical parameter
        PSO::SavePP(pp, pp_filename); 
    }
    else{
        PSO::FetchPP(pp, pp_filename); 
    }

    size_t LEN = size_t(pow(2, 20)); 
    std::cout << "number of elements = " << LEN << std::endl; 

    std::string testcase_filename = "PSO.testcase"; 
    
    // generate test instance (must be same for server and client)
    PSOTestCase testcase; 
    if(!FileExist(testcase_filename)){
        testcase = GenTestCase(LEN); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
    PrintSplitLine('-'); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: first start receiver, then start sender) ==> ";  
    std::getline(std::cin, party); // first the server, then the client
    PrintSplitLine('-'); 

    if(current == PSI){
        if(party == "receiver"){
            NetIO server("server", "", 8080);
            std::vector<block> vec_intersection_prime = PSO::PSI::Receive(server, pp, testcase.vec_X, testcase.LEN);

            std::set<block, BlockCompare> set_diff_result = 
            ComputeSetDifference(vec_intersection_prime, testcase.vec_intersection);  
            if(set_diff_result.size() == 0) std::cout << "PSI test succeeds" << std::endl; 
            else{
                std::cout << "PSI test fails" << std::endl;
                for(auto var: set_diff_result) Block::PrintBlock(var); 
            }
        }
    
        if(party == "sender"){
            NetIO client("client", "127.0.0.1", 8080);        
            PSO::PSI::Send(client, pp, testcase.vec_Y, testcase.LEN);
        } 
    }


    if(current == PSU){
        if(party == "receiver"){
            NetIO server("server", "", 8080);
            std::vector<block> vec_union_prime = PSO::PSU::Receive(server, pp, testcase.vec_X, testcase.LEN);
            
            std::set<block, BlockCompare> set_diff_result = ComputeSetDifference(vec_union_prime, testcase.vec_union);  
            if(set_diff_result.size() == 0) std::cout << "PSU test succeeds" << std::endl; 
            else{
                std::cout << "PSU test fails" << std::endl;
                for(auto var: set_diff_result) Block::PrintBlock(var); 
            }
        }
    
        if(party == "sender"){
            NetIO client("client", "127.0.0.1", 8080);        
            PSO::PSU::Send(client, pp, testcase.vec_Y, testcase.LEN);
        } 
    }

    if(current == PSI_card){
        if(party == "receiver"){
            NetIO server("server", "", 8080);
            size_t CARDINALITY = PSO::PSIcard::Receive(server, pp, testcase.vec_X, testcase.LEN);
 
            if(CARDINALITY == testcase.CARDINALITY) std::cout << "PSI-card test succeeds" << std::endl; 
            else std::cout << "PSI-card test fails" << std::endl; 
        }
    
        if(party == "sender"){
            NetIO client("client", "127.0.0.1", 8080);        
            PSO::PSIcard::Send(client, pp, testcase.vec_Y, testcase.LEN);
        } 
    }

    if(current == PSI_sum){
        if(party == "receiver"){
            NetIO server("server", "", 8080);
            int64_t SUM = PSO::PSIsum::Receive(server, pp, testcase.vec_X, testcase.LEN);
 
            if(SUM == testcase.SUM) std::cout << "PSI-sum test succeeds" << std::endl; 
            else std::cout << "PSI-sum test fails" << std::endl; 

            std::cout << testcase.SUM << std::endl;
            std::cout << SUM << std::endl;
        }
    
        if(party == "sender"){
            NetIO client("client", "127.0.0.1", 8080);        
            PSO::PSIsum::Send(client, pp, testcase.vec_Y, testcase.vec_label, testcase.LEN);
        } 
    }

    CRYPTO_Finalize();   
    
    return 0; 
}