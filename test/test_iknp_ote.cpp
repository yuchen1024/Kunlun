//#define DEBUG

#include "../ot/iknp_ote.hpp"

void test_sender(IKNPOTE::PP &pp, std::vector<block> &vec_m0, std::vector<block> &vec_m1, size_t EXTEND_LEN)
{
    NetIO server("server", "", 8080); 
	IKNPOTE::Send(server, pp, vec_m0, vec_m1, EXTEND_LEN);
}

void test_receiver(IKNPOTE::PP &pp, std::vector<block> &vec_result_prime, 
				   std::vector<uint8_t> &vec_selection_bit, size_t EXTEND_LEN)
{
	// receiver play the role of client 
	NetIO client("client", "127.0.0.1", 8080); 
	IKNPOTE::Receive(client, pp, vec_result_prime, vec_selection_bit, EXTEND_LEN);
}

void test_iknp_ote(std::string& party, size_t EXTEND_LEN) 
{
    PrintSplitLine('-'); 

    IKNPOTE::PP pp; 
	IKNPOTE::Setup(pp); 

	std::vector<block> vec_result(EXTEND_LEN); 
	std::vector<block> vec_result_prime(EXTEND_LEN);
	
	PRG::Seed seed; 
	PRG::SetSeed(seed, fix_key, 0); // initialize PRG
	std::vector<block> vec_m0 = PRG::GenRandomBlocks(seed, EXTEND_LEN);
	std::vector<block> vec_m1 = PRG::GenRandomBlocks(seed, EXTEND_LEN);
	
	std::vector<uint8_t> vec_selection_bit = PRG::GenRandomBits(seed, EXTEND_LEN);

	for (auto i = 0; i < EXTEND_LEN; i++){
		if(vec_selection_bit[i] == 0) vec_result[i] = vec_m0[i]; 
		else vec_result[i] = vec_m1[i]; 
	}

	if (party == "receiver")
	{
		test_receiver(pp, vec_result_prime, vec_selection_bit, EXTEND_LEN); 

		if(Block::Compare(vec_result, vec_result_prime, EXTEND_LEN) == true){
			std::cout << "IKNP OTE test succeeds" << std::endl; 
		} 
        else{
            std::cout << "IKNP OTE test fails" << std::endl;  
        }
	}

	if (party == "sender")
	{
		test_sender(pp, vec_m0, vec_m1, EXTEND_LEN); 
	}

}


void test_one_sided_sender(IKNPOTE::PP &pp, std::vector<block> &vec_m, size_t EXTEND_LEN)
{
    NetIO server("server", "", 8080); 
    IKNPOTE::OnesidedSend(server, pp, vec_m, EXTEND_LEN);
}

void test_one_sided_receiver(IKNPOTE::PP &pp, std::vector<block> &vec_result_prime, 
                             std::vector<uint8_t> &vec_selection_bit, size_t EXTEND_LEN)
{
    // receiver play the role of client 
    
    NetIO client("client", "127.0.0.1", 8080); 
    IKNPOTE::OnesidedReceive(client, pp, vec_result_prime, vec_selection_bit, EXTEND_LEN);
}

void test_one_sided_iknp_ote(std::string& party, size_t EXTEND_LEN) 
{
    PrintSplitLine('-'); 
    IKNPOTE::PP pp; 
    IKNPOTE::Setup(pp); 

    std::vector<block> vec_result; 
    std::vector<block> vec_result_prime;
    
    PRG::Seed seed; 
    PRG::SetSeed(seed, fix_key, 0); // initialize PRG
    std::vector<block> vec_m = PRG::GenRandomBlocks(seed, EXTEND_LEN);
    
    std::vector<uint8_t> vec_selection_bit = PRG::GenRandomBits(seed, EXTEND_LEN);
    //for(auto i = 0; i < EXTEND_LEN; i++) vec_selection_bit[i] = 0; 

    for (auto i = 0; i < EXTEND_LEN; i++){
        if(vec_selection_bit[i] == 1) vec_result.emplace_back(vec_m[i]); 
        //PrintBlock(vec_result[i]); 
    }

    if (party == "receiver")
    {
        test_one_sided_receiver(pp, vec_result_prime, vec_selection_bit, EXTEND_LEN); 

        if (vec_result_prime.size()!=vec_result.size()){
            std::cout << "1-sided IKNP OTE test fails" << std::endl;
        }
        else{
            size_t LEN = vec_result.size(); 
            if(Block::Compare(vec_result, vec_result_prime, LEN) == true){
                std::cout << "1-sided IKNP OTE test succeeds" << std::endl; 
            }
            else{
                std::cout << "1-sided IKNP OTE test fails" << std::endl;
            } 
        }
    }
    if (party == "sender")
    {
        test_one_sided_sender(pp, vec_m, EXTEND_LEN); 
    }

}


int main()
{
	Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: start sender first) ==> ";  
    std::getline(std::cin, party); // first receiver (acts as server), then sender (acts as client)
	
    auto start_time = std::chrono::steady_clock::now(); 
	size_t EXTEND_LEN = size_t(pow(2, 10)); 
	std::cout << "The extend LEN = " << EXTEND_LEN << std::endl; 
	test_iknp_ote(party, EXTEND_LEN);

    //test_one_sided_iknp_ote(party, EXTEND_LEN); 
	
	ECGroup_Finalize(); 
    Context_Finalize();   
	return 0; 
}