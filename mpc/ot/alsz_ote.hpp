#ifndef KUNLUN_ALSZ_OTE_HPP_
#define KUNLUN_ALSZ_OTE_HPP_

#include "naor_pinkas_ot.hpp"
#include "../../utility/routines.hpp"
/*
 * ALSZ OT Extension
 * [REF] With optimization of "More Efficient Oblivious Transfer and Extensions for Faster Secure Computation"
 * https://eprint.iacr.org/2013/552.pdf
 */

const static size_t BASE_LEN = 128; // the default length of base OT

namespace ALSZOTE{

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

// implement random OT send
void RandomSend(NetIO &io, PP &pp, std::vector<block> &vec_K0, std::vector<block> &vec_K1, size_t EXTEND_LEN)
{
    /* 
    ** Phase 1: sender obtains a random blended matrix Q of matrix T and U from receiver
    ** T and U are tall and skinny matrix, to use base OT oblivious transfer T and U, 
    ** the sender first oblivous get 1-out-of-2 keys per column from receiver via base OT 
    ** receiver then send encryptions of the original column and shared column under k0 and k1 respectively
    */

    // prepare to receive a secret shared matrix Q from receiver
    size_t ROW_NUM = EXTEND_LEN;   // set row num as the length of long ot
    size_t COLUMN_NUM = pp.BASE_LEN;  // set column num as the length of base ot

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG seed

    // generate Phase 1 selection bit vector
    std::vector<uint8_t> vec_sender_selection_bit = PRG::GenRandomBits(seed, COLUMN_NUM); 

    // first receive 1-out-2 two keys from the receiver 
    std::vector<block> vec_Q_seed = NPOT::Receive(io, pp.baseOT, vec_sender_selection_bit, COLUMN_NUM);

    std::cout << "ALSZ OTE [step 1]: Sender obliviously get " << BASE_LEN 
              << " number of keys from Receiver via base OT" << std::endl; 
    /* 
    ** invoke base OT COLUMN_NUM times to obtain a matrix Q
    ** after receiving the key, begin to receive ciphertexts
    */

    #ifdef DEBUG
        std::cout << "ALSZ OTE: Sender obliviuosly get "<< COLUMM_NUM << " number of seeds from Receiver" << std::endl; 
    #endif

    std::vector<block> Q(ROW_NUM/128*COLUMN_NUM); // size = ROW_NUM/128 * COLUMN_NUM 
    std::vector<block> Q_column; // size = ROW_NUM/128
    // compute Q
    for(auto j = 0; j < COLUMN_NUM; j++){
        PRG::ReSeed(seed, &vec_Q_seed[j], 0); 
        Q_column = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        //Q.insert(Q.end(), Q_column.begin(), Q_column.end());
        memcpy(Q.data()+ROW_NUM/128*j, Q_column.data(), ROW_NUM/8);   
    } 

    std::vector<block> P(ROW_NUM/128 * COLUMN_NUM); 
    io.ReceiveBlocks(P.data(), ROW_NUM/128 * COLUMN_NUM); 

    // compute Q XOR sP
    for(auto j = 0; j < COLUMN_NUM; j++){
        for(auto i = 0; i < ROW_NUM/128; i++){
            if(vec_sender_selection_bit[j] == 1){
                Q[j*ROW_NUM/128 + i] ^= P[j*ROW_NUM/128 + i]; 
            }
        }
    }

    // transpose Q XOR sP 
    std::vector<block> Q_transpose(ROW_NUM/128 * COLUMN_NUM);  
    BitMatrixTranspose((uint8_t*)Q.data(), COLUMN_NUM, ROW_NUM, (uint8_t*)Q_transpose.data());  

    #ifdef DEBUG
        std::cout << "ALSZ OTE: Sender transposes matrix Q XOR sP" << std::endl; 
    #endif

    // generate dense representation of selection block
    std::vector<block> vec_sender_selection_block(COLUMN_NUM/128); 
    Block::FromSparseBytes(vec_sender_selection_bit.data(), COLUMN_NUM, vec_sender_selection_block.data(), COLUMN_NUM/128); 

    // begin to transmit the real message
    std::vector<block> vec_outer_C0(ROW_NUM); 
    std::vector<block> vec_outer_C1(ROW_NUM); 

    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < ROW_NUM; i++)
    {
        std::vector<block> Q_row(COLUMN_NUM/128);
        memcpy(Q_row.data(), Q_transpose.data()+i*COLUMN_NUM/128, COLUMN_NUM/8); 
        vec_K0[i] = Hash::FastBlocksToBlock(Q_row); 
        vec_K1[i] = Hash::FastBlocksToBlock(Block::XOR(Q_row, vec_sender_selection_block));
    }
}

// implement random receive: note this random ot is slightly different from Beaver's ROT
// cause receiver can choose selection bit itself
void RandomReceive(NetIO &io, PP &pp, std::vector<block> &vec_K, 
                    std::vector<uint8_t> &vec_receiver_selection_bit, size_t EXTEND_LEN)
{
    // prepare a random matrix
    size_t ROW_NUM = EXTEND_LEN; 
    size_t COLUMN_NUM = pp.BASE_LEN; 

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    PRG::Seed seed = PRG::SetSeed(nullptr, 0); 

    // generate two seed vector to generate two pseudorandom matrixs 
    std::vector<block> vec_T_seed = PRG::GenRandomBlocks(seed, COLUMN_NUM);
    std::vector<block> vec_U_seed = PRG::GenRandomBlocks(seed, COLUMN_NUM);


    // Phase 1: first transmit 1-out-2 key to sender    
    NPOT::Send(io, pp.baseOT, vec_T_seed, vec_U_seed, COLUMN_NUM); 

    std::cout << "ALSZ OTE [step 1]: Receiver transmits "<< COLUMN_NUM << " number of seeds to Sender via base OT" 
              << std::endl; 
    
    // block representations for matrix T, U, and P: size = ROW_NUM/128*COLUMN_NUM
    std::vector<block> T(ROW_NUM/128*COLUMN_NUM);
    std::vector<block> P(ROW_NUM/128*COLUMN_NUM);

    std::vector<block> T_column, U_column, P_column; 

    // generate the dense representation of selection block
    std::vector<block> vec_receiver_selection_block(ROW_NUM/128); 
    Block::FromSparseBytes(vec_receiver_selection_bit.data(), ROW_NUM, vec_receiver_selection_block.data(), ROW_NUM/128); 
    
    for(auto j = 0; j < COLUMN_NUM; j++){
        // generate two random matrixs
        PRG::ReSeed(seed, &vec_T_seed[j], 0); 
        T_column = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        //T.insert(T.end(), T_column.begin(), T_column.end()); 
        memcpy(T.data()+ROW_NUM/128*j, T_column.data(), ROW_NUM/8); 

        PRG::ReSeed(seed, &vec_U_seed[j], 0);  
        U_column = PRG::GenRandomBlocks(seed, ROW_NUM/128); 
        
        // generate adjust matrix  
        std::vector<block> P_column = Block::XOR(T_column, U_column); // T xor U
        P_column = Block::XOR(P_column, vec_receiver_selection_block); // T xor U xor selection_block
        //P.insert(P.end(), P_column.begin(), P_column.end());
        memcpy(P.data()+ROW_NUM/128*j, P_column.data(), ROW_NUM/8);  
    } 

    // Phase 1: transmit adjust bit matrix
    io.SendBlocks(P.data(), ROW_NUM/128*COLUMN_NUM); 
    std::cout << "ALSZ OTE [step 2]: Receiver ===> " << ROW_NUM << "*" << COLUMN_NUM << " adjust bit matrix ===> Sender" 
              << " [" << (double)ROW_NUM/128*COLUMN_NUM*16/(1024*1024) << " MB]" << std::endl;

    // transpose T
    std::vector<block> T_transpose(ROW_NUM/128 * COLUMN_NUM); 
    BitMatrixTranspose((uint8_t*)T.data(), COLUMN_NUM, ROW_NUM, (uint8_t*)T_transpose.data());

    #ifdef DEBUG
        std::cout << "ALSZ OTE: Receiver transposes matrix T" << std::endl; 
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

    
    std::cout << "ALSZ OTE [step 3]: Sender ===> (vec_C0, vec_C1) ===> Receiver" 
              << "[" << (double)ROW_NUM*16*2/(1024*1024) << " MB]" << std::endl; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "ALSZ OTE: Sender side takes time " 
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
        std::cout << "ALSZ OTE: Receiver get "<< ROW_NUM << " pair of ciphertexts from Sender" << std::endl; 
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
        std::cout << "ALSZ OTE: Receiver obtains "<< ROW_NUM << " number of messages from Sender" << std::endl; 
        PrintSplitLine('*'); 
    #endif

    std::cout << "ALSZ OTE [step 4]: Receiver obtains vec_m" << std::endl; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "ALSZ OTE: Receiver side takes time " 
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

    std::cout << "ALSZ OTE [step 3]: Sender ===> vec_C ===> Receiver" << " [" 
              << (double)ROW_NUM*16/(1024*1024) << " MB]" << std::endl;

    #ifdef DEBUG
        std::cout << "ALSZ OTE: Sender sends "<< ROW_NUM << " number of ciphertexts to receiver" << std::endl; 
        PrintSplitLine('*'); 
    #endif

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "ALSZ OTE: Sender side takes time " 
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
        std::cout << "ALSZ OTE: Receiver get "<< ROW_NUM << " number of ciphertexts from Sender" << std::endl; 
        PrintSplitLine('*'); 
    #endif

    std::cout << "ALSZ OTE [step 4]: Receiver obtains vec_m" << std::endl; 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "ALSZ OTE: Receiver side takes time " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 

    return vec_result; 
}

}
#endif
