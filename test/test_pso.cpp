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
    std::vector<BigInt> vec_value; // vec_Y's value
    std::vector<uint8_t> vec_indication_bit; // X[i] = Y[i] iff b[i] = 1 
    std::vector<block> vec_intersection; // for PSI 
    std::vector<block> vec_union; // for PSU
    BigInt SUM;  // for PSI-sum: the sum of intersection labels
    size_t UNION_CARDINALITY; 
    size_t INTERSECTION_CARDINALITY; // for cardinality
    size_t LEN; // size of set 
    BigInt MAX; // the maximum value of each value
};

// LEN is the cardinality of two sets
PSOTestCase GenTestCase(size_t LEN)
{
    PSOTestCase testcase;
    testcase.LEN = LEN; 

    //PRG::Seed seed = PRG::SetSeed(PRG::fixed_salt, 0); // initialize PRG
    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, LEN);
    testcase.vec_indication_bit = PRG::GenRandomBits(seed, LEN); 

    testcase.MAX = size_t(pow(2, 10)); 
    testcase.vec_value = GenRandomBigIntVectorLessThan(LEN, testcase.MAX); 
    testcase.INTERSECTION_CARDINALITY = 0; 
    testcase.SUM = bn_0;
    testcase.vec_union = testcase.vec_X; 
    
    for(auto i = 0; i < LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_Y[i] = testcase.vec_X[i];
            testcase.INTERSECTION_CARDINALITY++; 
            testcase.SUM += testcase.vec_value[i];  
            testcase.vec_intersection.emplace_back(testcase.vec_Y[i]); 
        }
        else{
            testcase.vec_union.emplace_back(testcase.vec_Y[i]); 
        }
    }
    testcase.UNION_CARDINALITY = 2*LEN - testcase.INTERSECTION_CARDINALITY;  

    return testcase; 
}

void PrintTestCase(PSOTestCase testcase)
{
    PrintSplitLine('-'); 
    std::cout << "TESTCASE INFO >>>" << std::endl;
    std::cout << "ELEMENT NUM = " << testcase.LEN << std::endl;
    std::cout << "UNION CARDINALITY = " << testcase.UNION_CARDINALITY << std::endl; 
    std::cout << "INTERSECTION CARDINALITY = " << testcase.INTERSECTION_CARDINALITY << std::endl; 
    testcase.SUM.PrintInDec("INTERSECTION SUM"); 
    PrintSplitLine('-'); 
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
    fout << testcase.UNION_CARDINALITY;
    fout << testcase.INTERSECTION_CARDINALITY; 
    fout << testcase.SUM; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_value;
    fout << testcase.vec_indication_bit;
    fout << testcase.vec_intersection; 
    fout << testcase.vec_union; 

    fout << testcase.MAX; 

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
    fin >> testcase.UNION_CARDINALITY;
    fin >> testcase.INTERSECTION_CARDINALITY; 
    fin >> testcase.SUM; 

    testcase.vec_X.resize(testcase.LEN); 
    testcase.vec_Y.resize(testcase.LEN); 
    testcase.vec_value.resize(testcase.LEN);
    testcase.vec_indication_bit.resize(testcase.LEN); 
    testcase.vec_intersection.resize(testcase.INTERSECTION_CARDINALITY); 
    testcase.vec_union.resize(testcase.UNION_CARDINALITY);  

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_value;
    fin >> testcase.vec_indication_bit;
    fin >> testcase.vec_intersection; 
    fin >> testcase.vec_union; 

    fin >> testcase.MAX;

    fin.close(); 
}

int main()
{
    CRYPTO_Initialize(); 

    PSO_type current = PSI_card_sum; 

    switch(current) {
        case PSI: std::cout << "PSI"; break; 
        case PSU: std::cout << "PSU"; break; 
        case PSI_card: std::cout << "PSI-card"; break; 
        case PSI_card_sum: std::cout << "PSI-card-sum"; break; 
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

    //std::cout << "number of elements = " << LEN << std::endl; 

    std::string testcase_filename = "PSO.testcase"; 
    
    // generate test instance (must be same for server and client)
    PSOTestCase testcase; 
    if(!FileExist(testcase_filename)){
        size_t LEN = size_t(pow(2, 20)); 
        testcase = GenTestCase(LEN); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        FetchTestCase(testcase, testcase_filename);
    }
    PrintTestCase(testcase); 

    std::string party;
    std::cout << "please select your role between sender and receiver ";  

    if(current == PSI){
        std::cout << "(hint: first start receiver, then start sender) ==> "; 

        std::getline(std::cin, party);
        PrintSplitLine('-'); 
        
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
        std::getline(std::cin, party);
        PrintSplitLine('-'); 

        std::cout << "(hint: first start receiver, then start sender) ==> ";  
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
        std::cout << "(hint: first start receiver, then start sender) ==> ";  
        
        std::getline(std::cin, party);
        PrintSplitLine('-'); 

        if(party == "receiver"){
            NetIO server("server", "", 8080);
            size_t CARDINALITY = PSO::PSIcard::Receive(server, pp, testcase.vec_X, testcase.LEN);
 
            if(CARDINALITY == testcase.INTERSECTION_CARDINALITY){
                std::cout << "PSI-card test succeeds" << std::endl; 
            }
            else{
                std::cout << "PSI-card test fails" << std::endl; 
            }
        }
    
        if(party == "sender"){
            NetIO client("client", "127.0.0.1", 8080);        
            PSO::PSIcard::Send(client, pp, testcase.vec_Y, testcase.LEN);
        } 
    }

    if(current == PSI_card_sum){
        std::cout << "(hint: first start sender, then start receiver) ==> ";  

        std::getline(std::cin, party);
        PrintSplitLine('-'); 

        if(party == "sender"){
            NetIO server("server", "", 8080);

            size_t CARDINALITY = PSO::PSIcardsum::Send(server, pp, testcase.vec_X, testcase.LEN); 

            std::cout << "INTERSECTION CARDINALITY = " << CARDINALITY << std::endl;

            if(CARDINALITY == testcase.INTERSECTION_CARDINALITY){
                std::cout << "PSI-card-sum test succeeds" << std::endl; 
            }
            else{
                std::cout << "PSI-card-sum test fails" << std::endl; 
            }

        }
    
        if(party == "receiver"){
            NetIO client("client", "127.0.0.1", 8080);        

            size_t CARDINALITY; 
            BigInt SUM; 
            std::tie(CARDINALITY, SUM) = PSO::PSIcardsum::Receive(client, pp, testcase.vec_Y, testcase.vec_value, testcase.LEN);

            std::cout << "INTERSECTION CARDINALITY = " << CARDINALITY << std::endl;
            SUM.PrintInDec("INTERSECTION SUM");
 
            if(CARDINALITY == testcase.INTERSECTION_CARDINALITY && SUM == testcase.SUM){
                std::cout << "PSI-card-sum test succeeds" << std::endl; 
            }
            else{
                std::cout << "PSI-card-sum test fails" << std::endl; 
            }
        } 
    }

    CRYPTO_Finalize();   
    
    return 0; 
}