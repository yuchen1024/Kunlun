#include "../ot/iknp_ote.hpp"

void test_sender(IKNPOTE::PP &pp, std::vector<block> &vec_m0, std::vector<block> &vec_m1, size_t EXTEND_LEN)
{
	NetIO server("server", "127.0.0.1", 8080); 
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
	IKNPOTE::PP pp; 
	IKNPOTE::Setup(pp); 

	std::vector<block> vec_result(EXTEND_LEN); 
	std::vector<block> vec_result_prime(EXTEND_LEN);
	
	PRG::Seed seed; 
	PRG::SetSeed(seed, fix_key, 0); // initialize PRG
	std::vector<block> vec_m0 = PRG::GenRandomBlocks(seed, EXTEND_LEN);
	std::vector<block> vec_m1 = PRG::GenRandomBlocks(seed, EXTEND_LEN);
	
	std::vector<uint8_t> vec_selection_bit = PRG::GenRandomBits(seed, EXTEND_LEN);
	//for(auto i = 0; i < EXTEND_LEN; i++) vec_selection_bit[i] = 0; 

	for (auto i = 0; i < EXTEND_LEN; i++){
		if(vec_selection_bit[i] == 0) vec_result[i] = vec_m0[i]; 
		else vec_result[i] = vec_m1[i]; 
		//PrintBlock(vec_result[i]); 
	}

	if (party == "receiver")
	{
		test_receiver(pp, vec_result_prime, vec_selection_bit, EXTEND_LEN); 

		for (auto i = 0; i < EXTEND_LEN; i++){
			if(vec_selection_bit[i] == 0){ 
				vec_result[i] = vec_m0[i];
				//std::cout << "the " << i <<"th selection bit = " << 0 << std::endl;  				 
			}
			else{
				vec_result[i] = vec_m1[i];
				//std::cout << "the " << i <<"th selection bit = " << 1 << std::endl;
			}  
			//PrintBlock(vec_result_prime[i]); 

			// std::cout << "vec_outer_C0[" << i <<"] =";   
   //          PrintBlocks(vec_outer_C0.data(), 1);
		}

		// PrintBlocks(vec_result_prime.data(), 1); 
		// PrintBlocks(vec_result.data(), 1); 
		if(Block::Compare(vec_result, vec_result_prime, EXTEND_LEN) == true){
			std::cout << "IKNP OTE test succeeds" << std::endl; 
		} 
	}

	if (party == "sender")
	{
		test_sender(pp, vec_m0, vec_m1, EXTEND_LEN); 
	}

}

void test_endian()
{
	std::cout << sizeof(block) << std::endl; 
    std::vector<uint8_t> A(16); 
    A[0] = 0xFF;
    A[1] = 0x0F; 
    A[2] = 0xF0; 
    A[3] = 0xDD; 
    A[4] = 0xFF;
    A[5] = 0x01; 
    A[6] = 0x10; 
    A[7] = 0x25; 
    A[8] = 0x56;
    A[9] = 0x34; 
    A[10] = 0x67; 
    A[11] = 0x98; 
    A[12] = 0x22;
    A[13] = 0x41; 
    A[14] = 0x38; 
    A[15] = 0x66; 

    block B; 
    memcpy(&B, A.data(), 16); 

    //PrintBlock(B); 
}

void CompareMatrix(uint8_t *M1, uint8_t *M2, size_t ROW_NUM, size_t COLUMN_NUM)
{
	bool EQUAL = true; 
	for(auto i = 0; i < ROW_NUM/8 * COLUMN_NUM; i++){
		if(M1[i]!=M2[i]){
			std::cout << i << std::endl;
			EQUAL = false; 
			break;
		}
	}
	if (EQUAL) std::cout << "the two matrix are equal" << std::endl;
	else std::cout << "the two matrix are not equal" << std::endl;
}

void test_matrix_transpose()
{
	size_t ROW_NUM = 1024*1024; 
    size_t COLUMN_NUM = 128;

    PRG::Seed seed; 
    PRG::SetSeed(seed, nullptr, 0); 
    std::vector<uint8_t> T1 = PRG::GenRandomBitMatrix(seed, ROW_NUM, COLUMN_NUM); 
    //PrintBitMatrix(T1.data(), ROW_NUM, COLUMN_NUM);  

    std::vector<uint8_t> T2(ROW_NUM/8 * COLUMN_NUM); 
    // SSE_BitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());
    BitMatrixTranspose(T1.data(), ROW_NUM, COLUMN_NUM, T2.data());
    //PrintBitMatrix(T2.data(), COLUMN_NUM, ROW_NUM); 

    std::vector<uint8_t> T3(ROW_NUM/8 * COLUMN_NUM); 
    // SSE_BitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());
    BitMatrixTranspose(T2.data(), COLUMN_NUM, ROW_NUM, T3.data());
    //PrintBitMatrix(T3.data(), ROW_NUM, COLUMN_NUM);

    CompareMatrix(T1.data(), T3.data(), ROW_NUM, COLUMN_NUM); 
}

int main()
{
	Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1); 

    // test_matrix_transpose(); 


    std::string party;
    std::cout << "please select your role between sender and receiver (hint: start sender first) ==> ";  
    std::getline(std::cin, party); // first receiver (acts as server), then sender (acts as client)
	
    auto start_time = std::chrono::steady_clock::now(); 
	//size_t EXTEND_LEN = size_t(pow(2, 10)); 
	size_t EXTEND_LEN = 1024*1024; 
	std::cout << "the extend len = " << EXTEND_LEN << std::endl; 
	test_iknp_ote(party, EXTEND_LEN);
	auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "IKNP OTE takes time (2^10 scale) = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;




	ECGroup_Finalize(); 
    Context_Finalize();   
	return 0; 
}