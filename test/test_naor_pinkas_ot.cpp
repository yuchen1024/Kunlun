#include "../ot/naor_pinkas_ot.hpp"


void test_sender(NPOT::PP &pp, std::vector<block> &vec_m0, std::vector<block> &vec_m1, size_t LEN)
{
	NetIO client("client", "127.0.0.1", 8080); 
	NPOT::Send(client, pp, vec_m0, vec_m1, LEN);
}

void test_receiver(NPOT::PP &pp, std::vector<block> &vec_result_prime, std::vector<uint8_t> &vec_selection_bit, size_t LEN)
{
	NetIO server("server", "", 8080); 
	NPOT::Receive(server, pp, vec_result_prime, vec_selection_bit, LEN);
}

void test_naor_pinkas_ot(std::string& party, size_t LEN) {

	NPOT::PP pp; 
	NPOT::Setup(pp); 

	std::vector<block> vec_result(LEN); 
	std::vector<block> vec_result_prime(LEN);
	
	PRG::Seed seed; 
	PRG::SetSeed(seed, fix_key, 0); // initialize PRG
	std::vector<block> vec_m0 = PRG::GenRandomBlocks(seed, LEN);
	std::vector<block> vec_m1 = PRG::GenRandomBlocks(seed, LEN);
	
	std::vector<uint8_t> vec_selection_bit = PRG::GenRandomBits(seed, LEN);

	for (auto i = 0; i < LEN; i++){
		if(vec_selection_bit[i] == 0) vec_result[i] = vec_m0[i]; 
		else vec_result[i] = vec_m1[i]; 
	}

	if (party == "receiver")
	{
		test_receiver(pp, vec_result_prime, vec_selection_bit, LEN); 

		for (auto i = 0; i < LEN; i++){
			if(vec_selection_bit[i] == 0) vec_result[i] = vec_m0[i]; 
			else vec_result[i] = vec_m1[i]; 
		}

		if(Block::Compare(vec_result, vec_result_prime, LEN) == true){
			std::cout << "Naor-Pinkas OT test succeeds" << std::endl; 
		} 
	}

	if (party == "sender")
	{
		test_sender(pp, vec_m0, vec_m1, LEN); 
	}

}

int main()
{
	Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);  

    std::string party; 
    std::cout << "please select your role between sender and receiver (hint: start receiver first) ==> ";  
    std::getline(std::cin, party); // first receiver (acts as server), then sender (acts as client)
	test_naor_pinkas_ot(party, 128);

	ECGroup_Finalize(); 
    Context_Finalize();   
	return 0; 
}