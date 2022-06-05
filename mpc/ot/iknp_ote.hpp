#ifndef KUNLUN_IKNP_OTE_HPP_
#define KUNLUN_IKNP_OTE_HPP_

#include "naor_pinkas_ot.hpp"
/*
 * IKNP OT Extension
 * [REF] Implementation of "Extending oblivious transfers efficiently"
 * https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf
 */

namespace IKNPOTE{

using Serialization::operator<<; 
using Serialization::operator>>; 

// check if the parameters are legal
void CheckParameters(size_t ROW_NUM, size_t COLUMN_NUM)
{
    if (ROW_NUM%128 != 0 || COLUMN_NUM%128 != 0){
        std::cerr << "row or column parameters is wrong" << std::endl;
        exit(EXIT_FAILURE); 
    }
}

struct PP
{
    uint8_t malicious = 0; // false
    NPOT::PP baseOT;  
    size_t BASE_LEN = 128; // the default length of base OT 
};

void PrintPP(const PP &pp)
{
    std::cout << "malicious = " << int(pp.malicious) << std::endl; 
    NPOT::PrintPP(pp.baseOT);
    std::cout << "num of base OT = " << pp.BASE_LEN << std::endl; 
}


// serialize pp to stream
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
	fout << pp.baseOT; 
    fout << pp.malicious; 
    fout << pp.BASE_LEN; 
    return fout;
}


// deserialize pp from stream
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
	fin >> pp.baseOT; 
    fin >> pp.malicious; 
    fin >> pp.BASE_LEN; 
    return fin; 
}

PP Setup(size_t BASE_LEN)
{
    PP pp; 
    pp.malicious = 0; 
    pp.baseOT = NPOT::Setup();
    pp.BASE_LEN = BASE_LEN;   
    return pp;
}

// save pp to file
void SavePP(PP &pp, std::string pp_filename)
{
	std::ofstream fout; 
    fout.open(pp_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << pp; 
    fout.close(); 
}


// fetch pp from file
void FetchPP(PP &pp, std::string pp_filename)
{
	std::ifstream fin; 
    fin.open(pp_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> pp; 
    fin.close(); 
}


void RandomSend(NetIO &io, PP &pp, std::vector<block> &vec_K0, std::vector<block> &vec_K1, size_t EXTEND_LEN)
{
    // prepare to receive a secret shared matrix Q from receiver
    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG seed
    
    size_t ROW_NUM = EXTEND_LEN; 
    size_t COLUMN_NUM = pp.BASE_LEN; 

    // generate Phase 1 selection bit vector
    std::vector<uint8_t> vec_sender_selection_bit = GenRandomBits(seed, COLUMN_NUM); 

    // first receive 1-out-2 two keys from the receiver 
    std::vector<block> vec_inner_K = NPOT::Receive(io, pp.baseOT, vec_sender_selection_bit, COLUMN_NUM);

    std::cout << "IKNP OTE [step 1]: Sender obliviously get " << pp.BASE_LEN 
              << " number of keys from Receiver via base OT" << std::endl; 
    /* 
    ** invoke base OT BASE_LEN times to obtain a matrix Q
    ** after receiving the key, begin to receive ciphertexts
    */

    std::vector<block> vec_inner_C0(ROW_NUM/128); // 1 block = 128 bits 
    std::vector<block> vec_inner_C1(ROW_NUM/128); 

    std::vector<block> vec_inner_pad(ROW_NUM/128); // the one-time pad used to decrypt C
    std::vector<block> vec_inner_plaintext(ROW_NUM/128);   // the plaintext
    
    std::vector<block> Q(ROW_NUM/128 * COLUMN_NUM); // the matrix sender is going to receive from receiver (dense form)
    
    // for every column: prepare two column vectors
    for(auto j = 0; j < COLUMN_NUM; j++){
        // receiver the two ciphertexts
        io.ReceiveBlocks(vec_inner_C0.data(), ROW_NUM/128); 
        io.ReceiveBlocks(vec_inner_C1.data(), ROW_NUM/128);

        // use K[i] as seed to derive the one-time pad
        PRG::ReSeed(seed, &vec_inner_K[j], 0);    
        vec_inner_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);

        if(vec_sender_selection_bit[j] == 0){
            vec_inner_plaintext = Block::XOR(vec_inner_C0, vec_inner_pad);
        }
        else{
            vec_inner_plaintext = Block::XOR(vec_inner_C1, vec_inner_pad);   
        } 
        memcpy(Q.data()+j*ROW_NUM/128, vec_inner_plaintext.data(), ROW_NUM/8); 
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: Sender obliviously get "<< COLUMN_NUM << " pair of ciphertexts from Receiver" << std::endl; 
    #endif
    

    // transpose Q
    std::vector<block> Q_transpose(ROW_NUM/128 * COLUMN_NUM); 
    BitMatrixTranspose((uint8_t*)Q.data(), COLUMN_NUM, ROW_NUM, (uint8_t*)Q_transpose.data());  

    #ifdef DEBUG
        std::cout << "IKNP OTE: Sender transposes matrix Q" << std::endl; 
    #endif

    // generate dense representation of selection block
    std::vector<block> vec_sender_selection_block(COLUMN_NUM/128); 
    Block::FromSparseBytes(vec_sender_selection_bit.data(), COLUMN_NUM, vec_sender_selection_block.data(), COLUMN_NUM/128); 

    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ROW_NUM; i++){
        std::vector<block> Q_row_block(COLUMN_NUM/128);
        memcpy(Q_row_block.data(), Q_transpose.data()+i*COLUMN_NUM/128, COLUMN_NUM/8); 
        vec_K0[i] = Hash::FastBlocksToBlock(Q_row_block); 
        vec_K1[i] = Hash::FastBlocksToBlock(Block::XOR(Q_row_block, vec_sender_selection_block));
    }
}

void RandomReceive(NetIO &io, PP &pp, std::vector<block> &vec_K, 
                    std::vector<uint8_t> &vec_receiver_selection_bit, size_t EXTEND_LEN)
{
    PRG::Seed seed = PRG::SetSeed(nullptr, 0); 

    size_t ROW_NUM = EXTEND_LEN;
    size_t COLUMN_NUM = pp.BASE_LEN; 

    std::vector<block> T = PRG::GenRandomBitMatrix(seed, ROW_NUM, COLUMN_NUM); 

    std::vector<block> vec_inner_K0 = PRG::GenRandomBlocks(seed, COLUMN_NUM);
    std::vector<block> vec_inner_K1 = PRG::GenRandomBlocks(seed, COLUMN_NUM);

    // Phase 1: first transmit 1-out-2 key to sender
    
    NPOT::Send(io, pp.baseOT, vec_inner_K0, vec_inner_K1, COLUMN_NUM); 

    std::cout << "IKNP OTE [step 1]: Receiver transmits "<< pp.BASE_LEN << " number of keys to Sender via base OT" 
              << std::endl; 

    // generate the dense representation of selection block
    std::vector<block> vec_receiver_selection_block(ROW_NUM/128); 
    Block::FromSparseBytes(vec_receiver_selection_bit.data(), ROW_NUM, vec_receiver_selection_block.data(), ROW_NUM/128); 

    // Phase 1: transmit ciphertext a.k.a. random shared matrix
    std::vector<block> vec_inner_m0(ROW_NUM/128); 
    std::vector<block> vec_inner_m1(ROW_NUM/128); 

    std::vector<block> vec_inner_C0(ROW_NUM/128); 
    std::vector<block> vec_inner_C1(ROW_NUM/128); 
    
    std::vector<block> vec_inner_pad(ROW_NUM/128);
    // for every column: prepare two column vectors
    for(auto j = 0; j < COLUMN_NUM; j++)
    {
        // set vec_m0 be the jth column of T
        memcpy(vec_inner_m0.data(), T.data() + j*ROW_NUM/128, ROW_NUM/8); 

        // set vec_m1 = vec_m0 xor selection_block
        vec_inner_m1 = Block::XOR(vec_inner_m0, vec_receiver_selection_block);

        PRG::ReSeed(seed, &vec_inner_K0[j], 0); 
        vec_inner_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        vec_inner_C0 = Block::XOR(vec_inner_m0, vec_inner_pad); 
        
        PRG::ReSeed(seed, &vec_inner_K1[j], 0); 
        vec_inner_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        vec_inner_C1 = Block::XOR(vec_inner_m1, vec_inner_pad);

        io.SendBlocks(vec_inner_C0.data(), ROW_NUM/128); 
        io.SendBlocks(vec_inner_C1.data(), ROW_NUM/128);
    }   

    std::cout << "IKNP OTE [step 2]: Receiver ===> 2 encrypted matrix ===> Sender" 
              << " [" << (double)COLUMN_NUM*ROW_NUM/128*16*2/(1024*1024) << " MB]" << std::endl; 
    
    std::vector<block> T_transpose(ROW_NUM/128 * COLUMN_NUM); 
    BitMatrixTranspose((uint8_t*)T.data(), COLUMN_NUM, ROW_NUM, (uint8_t*)T_transpose.data());

    #ifdef DEBUG
        std::cout << "IKNP OTE: Receiver transposes matrix T" << std::endl; 
    #endif

    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ROW_NUM; i++)
    {
        std::vector<block> T_row(COLUMN_NUM/128);  
        memcpy(T_row.data(), T_transpose.data()+i*COLUMN_NUM/128, COLUMN_NUM/8); 
        
        vec_K[i] = Hash::FastBlocksToBlock(T_row); 
    }  
}

void Send(NetIO &io, PP &pp, std::vector<block> &vec_m0, std::vector<block> &vec_m1, size_t EXTEND_LEN) 
{
    /* 
    ** Phase 1: sender obtains a random secret sharing matrix Q of matrix T from receiver
    ** T is a tall matrix, to use base OT oblivious transfer T, 
    ** the sender first oblivous get 1-out-of-2 keys per column from receiver via base OT 
    ** receiver then send encryptions of the original column and shared column under k0 and k1 respectively
    */
    PrintSplitLine('-'); 
	auto start_time = std::chrono::steady_clock::now(); 

    // prepare to receive a secret shared matrix Q from receiver
    size_t ROW_NUM = EXTEND_LEN;   // set row num as the length of long ot
    size_t COLUMN_NUM = pp.BASE_LEN;  // set column num as the length of base ot

    CheckParameters(ROW_NUM, COLUMN_NUM); 
    
    std::vector<block> vec_K0(ROW_NUM); 
    std::vector<block> vec_K1(ROW_NUM);

    RandomSend(io, pp, vec_K0, vec_K1, EXTEND_LEN);  

    // begin to transmit the real message
    std::vector<block> vec_outer_C0(ROW_NUM); 
    std::vector<block> vec_outer_C1(ROW_NUM); 

    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ROW_NUM; i++)
    {       
        vec_outer_C0[i] = vec_m0[i]^vec_K0[i]; 
        vec_outer_C1[i] = vec_m1[i]^vec_K1[i];
    }
    io.SendBlocks(vec_outer_C0.data(), ROW_NUM); 
    io.SendBlocks(vec_outer_C1.data(), ROW_NUM);

    
    std::cout << "IKNP OTE [step 3]: Sender ===> (vec_C0, vec_C1) ===> Receiver" 
              << "[" << (double)ROW_NUM*16*2/(1024*1024) << " MB]" << std::endl; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "IKNP OTE: Sender side takes time " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    PrintSplitLine('-'); 
}


std::vector<block> Receive(NetIO &io, PP &pp, std::vector<uint8_t> &vec_receiver_selection_bit, size_t EXTEND_LEN)
{
    PrintSplitLine('-'); 
  
    auto start_time = std::chrono::steady_clock::now(); 

    // prepare a random matrix
    size_t ROW_NUM = EXTEND_LEN; 
    size_t COLUMN_NUM = pp.BASE_LEN; 

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    // first act as sender in base OT
    std::vector<block> vec_K(ROW_NUM); 
    RandomReceive(io, pp, vec_K, vec_receiver_selection_bit, EXTEND_LEN); 

    // receiver real payloads
    std::vector<block> vec_outer_C0(ROW_NUM); 
    std::vector<block> vec_outer_C1(ROW_NUM); 

    io.ReceiveBlocks(vec_outer_C0.data(), ROW_NUM);
    io.ReceiveBlocks(vec_outer_C1.data(), ROW_NUM);

    #ifdef DEBUG
        std::cout << "IKNP OTE: Receiver get "<< ROW_NUM << " pair of ciphertexts from Sender" << std::endl; 
    #endif

    std::vector<block> vec_result(ROW_NUM);
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ROW_NUM; i++)
    {
        if(vec_receiver_selection_bit[i] == 0){
            vec_result[i] = vec_outer_C0[i]^vec_K[i]; 
        }
        else{
            vec_result[i] = vec_outer_C1[i]^vec_K[i];
        }
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: Receiver obtains "<< ROW_NUM << " number of messages from Sender" << std::endl; 
        PrintSplitLine('*'); 
    #endif

    std::cout << "IKNP OTE [step 4]: Receiver obtains vec_m" << std::endl; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "IKNP OTE: Receiver side takes time " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 

    return vec_result; 
}

void OnesidedSend(NetIO &io, PP &pp, std::vector<block> &vec_m, size_t EXTEND_LEN) 
{
    /* 
    ** Phase 1: sender obtains a random secret sharing matrix Q of matrix T from receiver
    ** T is a tall matrix, to use base OT oblivious transfer T, 
    ** the sender first oblivous get 1-out-of-2 keys per column from receiver via base OT 
    ** receiver then send encryptions of the original column and shared column under k0 and k1 respectively
    */	
    PrintSplitLine('-'); 
	
    auto start_time = std::chrono::steady_clock::now(); 

    // prepare to receive a secret shared matrix Q from receiver
    size_t ROW_NUM = EXTEND_LEN;   // set row num as the length of long ot
    size_t COLUMN_NUM = pp.BASE_LEN;  // set column num as the length of base ot

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    std::vector<block> vec_K0(ROW_NUM);
    std::vector<block> vec_K1(ROW_NUM); 

    RandomSend(io, pp, vec_K0, vec_K1, EXTEND_LEN); 

    // begin to transmit the real message
    std::vector<block> vec_outer_C(ROW_NUM);

    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ROW_NUM; i++)
    {
        vec_outer_C[i] = vec_m[i]^vec_K1[i];
    }
    io.SendBlocks(vec_outer_C.data(), ROW_NUM); 

    std::cout << "IKNP OTE [step 3]: Sender ===> vec_C ===> Receiver" << " [" 
              << (double)ROW_NUM*16/(1024*1024) << " MB]" << std::endl;

    #ifdef DEBUG
        std::cout << "IKNP OTE: Sender sends "<< ROW_NUM << " number of ciphertexts to receiver" << std::endl; 
        PrintSplitLine('*'); 
    #endif

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "IKNP OTE: Sender side takes time " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
}

// the size of vec_result = the hamming weight of vec_selection_bit
std::vector<block> OnesidedReceive(NetIO &io, PP &pp, std::vector<uint8_t> &vec_receiver_selection_bit, size_t EXTEND_LEN)
{
    PrintSplitLine('-'); 

    std::vector<block> vec_result;
    // first act as sender in base OT
    
    auto start_time = std::chrono::steady_clock::now(); 
    // prepare a random matrix
    size_t ROW_NUM = EXTEND_LEN; 
    size_t COLUMN_NUM = pp.BASE_LEN; 

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    std::vector<block> vec_K(ROW_NUM); 

    RandomReceive(io, pp, vec_K, vec_receiver_selection_bit, EXTEND_LEN);

    std::vector<block> vec_outer_C(ROW_NUM); 
    io.ReceiveBlocks(vec_outer_C.data(), ROW_NUM);

    for(auto i = 0; i < ROW_NUM; i++)
    {        
        // only decrypt when selection bit is 1
        if(vec_receiver_selection_bit[i] == 1){
            vec_result.emplace_back(vec_outer_C[i]^vec_K[i]);
        }
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: Receiver get "<< ROW_NUM << " number of ciphertexts from Sender" << std::endl; 
        PrintSplitLine('*'); 
    #endif

    std::cout << "IKNP OTE [step 4]: Receiver obtains vec_m" << std::endl; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "IKNP OTE: Receiver side takes time " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 

    return vec_result; 
}

}
#endif
