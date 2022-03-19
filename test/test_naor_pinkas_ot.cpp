#include "../mpc/ot/naor_pinkas_ot.hpp"

// here NUM denotes the number of base OT, also the length of vec_m
void GenTestCase(std::vector<block> &vec_m0, std::vector<block> &vec_m1, std::vector<uint8_t> &vec_selection_bit, 
                 std::vector<block> &vec_result, size_t NUM)
{	
	PRG::Seed seed; 
	PRG::SetSeed(seed, fix_key, 0); // initialize PRG
	vec_m0 = PRG::GenRandomBlocks(seed, NUM);
	vec_m1 = PRG::GenRandomBlocks(seed, NUM);	
	vec_selection_bit = PRG::GenRandomBits(seed, NUM);
	
	vec_result.resize(NUM); 
    for(auto i = 0; i < NUM; i++){
        if(vec_selection_bit[i] == 0) vec_result[i] = vec_m0[i];
        else vec_result[i] = vec_m1[i]; 
    }
}

void SaveTestCase(std::vector<block> &vec_m0, std::vector<block> &vec_m1, 
                  std::vector<uint8_t> &vec_selection_bit, std::vector<block> &vec_result, 
                  size_t NUM, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << NUM; 
    for(auto i = 0; i < NUM; i++) fout << vec_m0[i]; 
    for(auto i = 0; i < NUM; i++) fout << vec_m1[i]; 
    for(auto i = 0; i < NUM; i++) fout << vec_selection_bit[i]; 
	for(auto i = 0; i < NUM; i++) fout << vec_result[i]; 

    fout.close(); 
}

void FetchTestCase(std::vector<block> &vec_m0, std::vector<block> &vec_m1, 
                      std::vector<uint8_t> &vec_selection_bit, std::vector<block> &vec_result, 
                      size_t NUM, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> NUM; 
	vec_m0.resize(NUM); 
	vec_m1.resize(NUM); 
	vec_selection_bit.resize(NUM); 
	vec_result.resize(NUM); 
    for(auto i = 0; i < NUM; i++) fin >> vec_m0[i]; 
    for(auto i = 0; i < NUM; i++) fin >> vec_m1[i]; 
    for(auto i = 0; i < NUM; i++) fin >> vec_selection_bit[i]; 
	for(auto i = 0; i < NUM; i++) fin >> vec_result[i]; 

    fin.close(); 
}

int main()
{
	Global_Setup(); 
	Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  

	PrintSplitLine('-'); 
    std::cout << "Naor-Pinkas OT test begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "npot.pp"; 
    NPOT::PP pp; 
    if(!FileExist(pp_filename)){
        pp = NPOT::Setup(); 
        NPOT::SavePP(pp, pp_filename); 
    }
    else{
        NPOT::FetchPP(pp, pp_filename); 
    }

	// set instance size
    size_t NUM = 128; 
    std::cout << "number of base OT = " << NUM << std::endl; 

    std::string testcase_filename = "npot.testcase"; 
    std::vector<block> vec_m0; 
    std::vector<block> vec_m1; 
    std::vector<uint8_t> vec_selection_bit; 
	std::vector<block> vec_result; 
    if(!FileExist(testcase_filename)){
        GenTestCase(vec_m0, vec_m1, vec_selection_bit, vec_result, NUM); 
        SaveTestCase(vec_m0, vec_m1, vec_selection_bit, vec_result, NUM, testcase_filename); 
    }
    else{
        FetchTestCase(vec_m0, vec_m1, vec_selection_bit, vec_result, NUM, testcase_filename);
    }

    PrintSplitLine('-'); 

    std::string party; 
    std::cout << "please select your role between sender and receiver (hint: start receiver first) ==> ";  
    std::getline(std::cin, party); // first receiver (acts as server), then sender (acts as client)
	if (party == "receiver")
	{
		NetIO receiver_io("server", "", 8080);
		std::vector<block> vec_result_prime = Receive(receiver_io, pp, vec_selection_bit, NUM); 
		if(Block::Compare(vec_result, vec_result_prime) == true){
			std::cout << "Naor-Pinkas OT test succeeds" << std::endl; 
		} 
	}

	if (party == "sender")
	{
		NetIO sender_io("client", "127.0.0.1", 8080); 
		Send(sender_io, pp, vec_m0, vec_m1, NUM); 
	}


    PrintSplitLine('-'); 
    std::cout << "Naor-Pinkas OT test ends >>>" << std::endl; 
    PrintSplitLine('-'); 

	ECGroup_Finalize(); 
    Context_Finalize();   
	return 0; 
}