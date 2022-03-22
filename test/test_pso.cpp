#include "../mpc/pso/pso_from_mqrpmt.hpp"

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

    PRG::Seed seed; 
    PRG::SetSeed(seed, fix_key, 0); // initialize PRG
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

    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_X[i]; 
    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_Y[i];
    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_label[i];
    for(auto i = 0; i < testcase.LEN; i++) fout << testcase.vec_indication_bit[i]; 
    for(auto i = 0; i < testcase.CARDINALITY; i++) fout << testcase.vec_intersection[i];
    for(auto i = 0; i < 2*testcase.LEN - testcase.CARDINALITY; i++) fout << testcase.vec_union[i];  

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

    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_X[i]; 
    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_Y[i];
    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_label[i];
    for(auto i = 0; i < testcase.LEN; i++) fin >> testcase.vec_indication_bit[i]; 
    for(auto i = 0; i < testcase.CARDINALITY; i++) fin >> testcase.vec_intersection[i];
    for(auto i = 0; i < 2*testcase.LEN - testcase.CARDINALITY; i++) fin >> testcase.vec_union[i];  
    fin.close(); 
}

int main()
{
    Global_Setup(); 
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    PSO_type current = PSU; 

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
        pp = PSO::Setup("bloom", 40); // 50 is the statistical parameter
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
    std::cout << "please select your role between server and client (hint: start server first) ==> ";  
    std::getline(std::cin, party); // first the server, then the client

    if(current == PSI){
        if(party == "server"){
            NetIO server_io("server", "", 8080);
            std::vector<block> vec_intersection_prime = PSO::PSIServer(server_io, pp, testcase.vec_X, testcase.LEN);

            bool result = Block::Compare(testcase.vec_intersection, vec_intersection_prime); 
            if(result) std::cout << "PSI test succeeds" << std::endl; 
            else std::cout << "PSI test fails" << std::endl; 
        }
    
        if(party == "client"){
            NetIO client_io("client", "127.0.0.1", 8080);        
            PSO::PSIClient(client_io, pp, testcase.vec_Y, testcase.LEN);
        } 
    }


    if(current == PSU){
        if(party == "server"){
            NetIO server_io("server", "", 8080);
            std::vector<block> vec_union_prime = PSO::PSUServer(server_io, pp, testcase.vec_X, testcase.LEN);

            // bool result = Block::Compare(testcase.vec_union, vec_union_prime); 
            // if(result) std::cout << "PSU test succeeds" << std::endl; 
            // else std::cout << "PSU test fails" << std::endl; 
        }
    
        if(party == "client"){
            NetIO client_io("client", "127.0.0.1", 8080);        
            PSO::PSUClient(client_io, pp, testcase.vec_Y, testcase.LEN);
        } 
    }

    if(current == PSI_card){
        if(party == "server"){
            NetIO server_io("server", "", 8080);
            size_t CARDINALITY = PSO::PSIcardServer(server_io, pp, testcase.vec_X, testcase.LEN);
 
            if(CARDINALITY == testcase.CARDINALITY) std::cout << "PSI-card test succeeds" << std::endl; 
            else std::cout << "PSI-card test fails" << std::endl; 
        }
    
        if(party == "client"){
            NetIO client_io("client", "127.0.0.1", 8080);        
            PSO::PSIcardClient(client_io, pp, testcase.vec_Y, testcase.LEN);
        } 
    }

    if(current == PSI_sum){
        if(party == "server"){
            NetIO server_io("server", "", 8080);
            int64_t SUM = PSO::PSIsumServer(server_io, pp, testcase.vec_X, testcase.LEN);
 
            if(SUM == testcase.SUM) std::cout << "PSI-sum test succeeds" << std::endl; 
            else std::cout << "PSI-sum test fails" << std::endl; 

            std::cout << testcase.SUM << std::endl;
            std::cout << SUM << std::endl;
        }
    
        if(party == "client"){
            NetIO client_io("client", "127.0.0.1", 8080);        
            PSO::PSIsumClient(client_io, pp, testcase.vec_Y, testcase.vec_label, testcase.LEN);
        } 
    }

    ECGroup_Finalize(); 
    Context_Finalize();   
    return 0; 
}