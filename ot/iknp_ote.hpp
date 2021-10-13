#ifndef KUNLUN_IKNP_OTE_HPP_
#define KUNLUN_IKNP_OTE_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/block.hpp"
#include "../io/net_io_stream_channel.hpp"
#include "../ot/naor_pinkas_ot.hpp"

/*
 * IKNP OT Extension
 * [REF] Implementation of "Extending oblivious transfers efficiently"
 * https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf
 *
 * [REF] With optimization of "More Efficient Oblivious Transfer and Extensions for Faster Secure Computation"
 * https://eprint.iacr.org/2013/552.pdf
 * [REF] With optimization of "Better Concrete Security for Half-Gates Garbling (in the Multi-Instance Setting)"
 * https://eprint.iacr.org/2019/1168.pdf
 */

const static size_t BASE_LEN = 128; // the default length of base OT

// check if the parameters are legal
void CheckParameters(size_t ROW_NUM, size_t COLUMN_NUM)
{
    if (ROW_NUM%128 != 0 || COLUMN_NUM%128 != 0){
        std::cerr << "row or colulumn parameters is wrong" << std::endl;
        exit(EXIT_FAILURE); 
    }
}

namespace IKNPOTE{

struct PP
{
    bool malicious = false;
    ECPoint g;  
};

void Setup(PP &pp)
{
    pp.g = ECPoint(generator); 
}

void GetNPOTPP(PP &pp, NPOT::PP &pp_npot)
{
    pp_npot.g = pp.g; 
}

void Send(NetIO &io, PP &pp, std::vector<block> &vec_m0, std::vector<block> &vec_m1, size_t EXTEND_LEN) 
{
    /* 
    ** Phase 1: sender obtains a random secret sharing matrix Q of matrix T from receiver
    ** T is a tall matrix, to use base OT oblivious transfer T, 
    ** the sender first oblivous get 1-out-of-2 keys per column from receiver via base OT 
    ** receiver then send encryptions of the original column and shared column under k0 and k1 respectively
    */

    // prepare to receive a secret shared matrix Q from receiver
    size_t ROW_NUM = EXTEND_LEN;   // set row num as the length of long ot
    size_t COLUMN_NUM = BASE_LEN;  // set column num as the length of base ot

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    PRG::Seed seed; 
    PRG::SetSeed(seed, nullptr, 0); // initialize PRG seed

    // generate Phase 1 selection bit vector
    std::vector<uint8_t> vec_selection_bit(BASE_LEN);
    vec_selection_bit = GenRandomBits(seed, BASE_LEN); 
    // for(auto i = 0; i < vec_selection_bit.size(); i++) vec_selection_bit[i] = 0; 

    // first receive 1-out-2 two keys from the receiver 
    std::vector<block> vec_K(BASE_LEN); 
    NPOT::PP pp_npot; 
    GetNPOTPP(pp, pp_npot); 
    NPOT::Receive(io, pp_npot, vec_K, vec_selection_bit, BASE_LEN);
    #ifdef DEBUG
        PrintSplitLine('*'); 
        std::cout << "IKNP OTE: sender obliviuosly get "<< BASE_LEN << " number of keys from receiver" << std::endl; 
    #endif
    /* 
    ** invoke base OT BASE_LEN times to obtain a matrix Q
    ** after receiving the key, begin to receive ciphertexts
    */

    std::vector<block> vec_inner_C0(ROW_NUM/128); // 1 block = 128 bits 
    std::vector<block> vec_inner_C1(ROW_NUM/128); 

    std::vector<block> vec_pad(ROW_NUM/128); // the one-time pad used to decrypt C
    std::vector<block> vec_plaintext(ROW_NUM/128);   // the plaintext
    
    std::vector<uint8_t> Q(ROW_NUM/8 * COLUMN_NUM); // the matrix sender is going to receive from receiver (dense form)
    // for every column: prepare two column vectors
    for(auto j = 0; j < BASE_LEN; j++){
        // receiver the two ciphertexts
        io.ReceiveBlocks(vec_inner_C0.data(), ROW_NUM/128); 
        io.ReceiveBlocks(vec_inner_C1.data(), ROW_NUM/128);

        // use K[i] as seed to derive the one-time pad
        PRG::ReSeed(seed, &vec_K[j], 0);    
        vec_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);

        if(vec_selection_bit[j] == 0){
            vec_plaintext = Block::XOR(vec_inner_C0, vec_pad);
        }
        else{
            vec_plaintext = Block::XOR(vec_inner_C1, vec_pad);   
        } 
        Block::ToDenseBits(vec_plaintext.data(), ROW_NUM/128, Q.data()+j*ROW_NUM/8, ROW_NUM); 
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: sender obliviuosly get "<< BASE_LEN << " pair of ciphertexts from receiver" << std::endl; 
    #endif
    

    // transpose Q
    std::vector<uint8_t> Q_tanspose(ROW_NUM/8 * COLUMN_NUM); 
    empBitMatrixTranspose(Q.data(), ROW_NUM, COLUMN_NUM, Q_tanspose.data());  

    #ifdef DEBUG
        std::cout << "IKNP OTE: sender transposes matrix Q" << std::endl; 
    #endif

    // generate dense representation of selection block
    std::vector<block> vec_selection_block(BASE_LEN/128); 
    Block::FromSparseBits(vec_selection_bit.data(), BASE_LEN, vec_selection_block.data(), BASE_LEN/128); 


    // begin to transmit the real message
    std::vector<block> vec_outer_C0(ROW_NUM); 
    std::vector<block> vec_outer_C1(ROW_NUM); 

    for(auto i = 0; i < ROW_NUM; i++)
    {
        std::vector<block> Q_row_block(BASE_LEN/128);

        Block::FromDenseBits(Q_tanspose.data() + i*COLUMN_NUM/8, BASE_LEN, Q_row_block.data(), BASE_LEN/128); 
    
        //std::vector<block> K(BASE_LEN/128);
        
        vec_outer_C0[i] = vec_m0[i]^Hash::BlocksToBlock(Q_row_block); 
        vec_outer_C1[i] = vec_m1[i]^Hash::BlocksToBlock(Block::XOR(Q_row_block, vec_selection_block));
    }
    io.SendBlocks(vec_outer_C0.data(), ROW_NUM); 
    io.SendBlocks(vec_outer_C1.data(), ROW_NUM);

    #ifdef DEBUG
        std::cout << "IKNP OTE: sender sends "<< ROW_NUM << " pair of ciphertexts to receiver" << std::endl; 
        PrintSplitLine('*'); 
    #endif
}

void Receive(NetIO &io, PP &pp, std::vector<block> &vec_result, const std::vector<uint8_t> &vec_selection_bit, size_t EXTEND_LEN)
{
    // first act as sender in base OT
    
    // prepare a random matrix
    size_t ROW_NUM = EXTEND_LEN; 
    size_t COLUMN_NUM = BASE_LEN; 

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    PRG::Seed seed; 
    PRG::SetSeed(seed, nullptr, 0); 
    
    std::vector<uint8_t> T = PRG::GenRandomBitMatrix(seed, ROW_NUM, COLUMN_NUM); 

    std::vector<block> vec_K0 = PRG::GenRandomBlocks(seed, BASE_LEN);
    std::vector<block> vec_K1 = PRG::GenRandomBlocks(seed, BASE_LEN);

    // Phase 1: first transmit 1-out-2 key to sender
    NPOT::PP pp_npot; 
    GetNPOTPP(pp, pp_npot); 
    NPOT::Send(io, pp_npot, vec_K0, vec_K1, BASE_LEN); 

    #ifdef DEBUG
        PrintSplitLine('*'); 
        std::cout << "IKNP OTE: receiver sends "<< BASE_LEN << " number of keys to sender via base OT" << std::endl; 
    #endif

    // generate the dense representation of selection block
    std::vector<block> vec_selection_block(ROW_NUM/128); 
    Block::FromSparseBits(vec_selection_bit.data(), ROW_NUM, vec_selection_block.data(), ROW_NUM/128); 


    // Phase 1: transmit ciphertext a.k.a. random shared matrix
    std::vector<block> vec_m0(ROW_NUM/128); 
    std::vector<block> vec_m1(ROW_NUM/128); 

    std::vector<block> vec_inner_C0(ROW_NUM/128); 
    std::vector<block> vec_inner_C1(ROW_NUM/128); 
    
    std::vector<block> vec_pad(ROW_NUM/128);
    // for every column: prepare two column vectors
    for(auto j = 0; j < COLUMN_NUM; j++)
    {
        // set vec_m0 be the jth column of T
        Block::FromDenseBits(T.data() + j*ROW_NUM/8, ROW_NUM, vec_m0.data(), ROW_NUM/128); 

        // set vec_m1 = vec_m0 xor selection_block
        vec_m1 = Block::XOR(vec_m0, vec_selection_block);

        PRG::ReSeed(seed, &vec_K0[j], 0); 
        vec_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        vec_inner_C0 = Block::XOR(vec_m0, vec_pad); 
        
        PRG::ReSeed(seed, &vec_K1[j], 0); 
        vec_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        vec_inner_C1 = Block::XOR(vec_m1, vec_pad);

        io.SendBlocks(vec_inner_C0.data(), ROW_NUM/128); 
        io.SendBlocks(vec_inner_C1.data(), ROW_NUM/128);
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: receiver sends "<< COLUMN_NUM << " pair of ciphertexts to sender" << std::endl; 
    #endif
    
    std::vector<uint8_t> T_transpose(ROW_NUM/8 * COLUMN_NUM); 
    empBitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());

    #ifdef DEBUG
        std::cout << "IKNP OTE: receiver transposes matrix T" << std::endl; 
    #endif

    std::vector<block> vec_outer_C0(ROW_NUM); 
    std::vector<block> vec_outer_C1(ROW_NUM); 

    io.ReceiveBlocks(vec_outer_C0.data(), ROW_NUM);
    io.ReceiveBlocks(vec_outer_C1.data(), ROW_NUM);


    #ifdef DEBUG
        std::cout << "IKNP OTE: receiver get "<< ROW_NUM << " pair of ciphertexts from receiver" << std::endl; 
    #endif

    for(auto i = 0; i < ROW_NUM; i++)
    {
        std::vector<block> T_row_block(BASE_LEN/128);  
        Block::FromDenseBits(T_transpose.data()+i*COLUMN_NUM/8, BASE_LEN, T_row_block.data(), BASE_LEN/128); 
        
        if(vec_selection_bit[i] == 0){
            vec_result[i] = vec_outer_C0[i]^Hash::BlocksToBlock(T_row_block); 
        }
        else{
            vec_result[i] = vec_outer_C1[i]^Hash::BlocksToBlock(T_row_block);
        }
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: receiver obtains "<< ROW_NUM << " number of messages from receiver" << std::endl; 
        PrintSplitLine('*'); 
    #endif
}

void OnesidedSend(NetIO &io, PP &pp, std::vector<block> &vec_m, size_t EXTEND_LEN) 
{
    /* 
    ** Phase 1: sender obtains a random secret sharing matrix Q of matrix T from receiver
    ** T is a tall matrix, to use base OT oblivious transfer T, 
    ** the sender first oblivous get 1-out-of-2 keys per column from receiver via base OT 
    ** receiver then send encryptions of the original column and shared column under k0 and k1 respectively
    */

    // prepare to receive a secret shared matrix Q from receiver
    size_t ROW_NUM = EXTEND_LEN;   // set row num as the length of long ot
    size_t COLUMN_NUM = BASE_LEN;  // set column num as the length of base ot

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    PRG::Seed seed; 
    PRG::SetSeed(seed, nullptr, 0); // initialize PRG seed

    // generate Phase 1 selection bit vector
    std::vector<uint8_t> vec_selection_bit(BASE_LEN);
    vec_selection_bit = GenRandomBits(seed, BASE_LEN); 
    // for(auto i = 0; i < vec_selection_bit.size(); i++) vec_selection_bit[i] = 0; 

    // first receive 1-out-2 two keys from the receiver 
    std::vector<block> vec_K(BASE_LEN); 
    NPOT::PP pp_npot; 
    GetNPOTPP(pp, pp_npot); 
    NPOT::Receive(io, pp_npot, vec_K, vec_selection_bit, BASE_LEN);
    #ifdef DEBUG
        PrintSplitLine('*'); 
        std::cout << "1-sided IKNP OTE: sender obliviuosly get "<< BASE_LEN << " number of keys from receiver" << std::endl; 
    #endif
    /* 
    ** invoke base OT BASE_LEN times to obtain a matrix Q
    ** after receiving the key, begin to receive ciphertexts
    */

    std::vector<block> vec_inner_C0(ROW_NUM/128); // 1 block = 128 bits 
    std::vector<block> vec_inner_C1(ROW_NUM/128); 

    std::vector<block> vec_pad(ROW_NUM/128); // the one-time pad used to decrypt C
    std::vector<block> vec_plaintext(ROW_NUM/128);   // the plaintext
    
    std::vector<uint8_t> Q(ROW_NUM/8 * COLUMN_NUM); // the matrix sender is going to receive from receiver (dense form)
    // for every column: prepare two column vectors
    for(auto j = 0; j < BASE_LEN; j++){
        // receiver the two ciphertexts
        io.ReceiveBlocks(vec_inner_C0.data(), ROW_NUM/128); 
        io.ReceiveBlocks(vec_inner_C1.data(), ROW_NUM/128);

        // use K[i] as seed to derive the one-time pad
        PRG::ReSeed(seed, &vec_K[j], 0);    
        vec_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);

        if(vec_selection_bit[j] == 0){
            vec_plaintext = Block::XOR(vec_inner_C0, vec_pad);
        }
        else{
            vec_plaintext = Block::XOR(vec_inner_C1, vec_pad);   
        } 
        Block::ToDenseBits(vec_plaintext.data(), ROW_NUM/128, Q.data()+j*ROW_NUM/8, ROW_NUM); 
    }   

    #ifdef DEBUG
        std::cout << "1-sided IKNP OTE: sender obliviuosly get "<< BASE_LEN << " pair of ciphertexts from receiver" << std::endl; 
    #endif
    

    // transpose Q
    std::vector<uint8_t> Q_tanspose(ROW_NUM/8 * COLUMN_NUM); 
    empBitMatrixTranspose(Q.data(), ROW_NUM, COLUMN_NUM, Q_tanspose.data());  

    #ifdef DEBUG
        std::cout << "1-sided IKNP OTE: sender transposes matrix Q" << std::endl; 
    #endif

    // generate dense representation of selection block
    std::vector<block> vec_selection_block(BASE_LEN/128); 
    Block::FromSparseBits(vec_selection_bit.data(), BASE_LEN, vec_selection_block.data(), BASE_LEN/128); 


    // begin to transmit the real message
    block outer_C; 

    for(auto i = 0; i < ROW_NUM; i++)
    {
        std::vector<block> Q_row_block(BASE_LEN/128);
        Block::FromDenseBits(Q_tanspose.data() + i*COLUMN_NUM/8, BASE_LEN, Q_row_block.data(), BASE_LEN/128);
        outer_C = vec_m[i]^Hash::BlocksToBlock(Block::XOR(Q_row_block, vec_selection_block));
        io.SendBlock(outer_C); 
    }


    #ifdef DEBUG
        std::cout << "1-side IKNP OTE: sender sends "<< ROW_NUM << " number of ciphertexts to receiver" << std::endl; 
        PrintSplitLine('*'); 
    #endif
}

// the size of vec_result = the hamming weight of vec_selection_bit
void OnesidedReceive(NetIO &io, PP &pp, std::vector<block> &vec_result, const std::vector<uint8_t> &vec_selection_bit, size_t EXTEND_LEN)
{
    // first act as sender in base OT
    
    // prepare a random matrix
    size_t ROW_NUM = EXTEND_LEN; 
    size_t COLUMN_NUM = BASE_LEN; 

    CheckParameters(ROW_NUM, COLUMN_NUM); 

    PRG::Seed seed; 
    PRG::SetSeed(seed, nullptr, 0); 
    
    std::vector<uint8_t> T = PRG::GenRandomBitMatrix(seed, ROW_NUM, COLUMN_NUM); 

    std::vector<block> vec_K0 = PRG::GenRandomBlocks(seed, BASE_LEN);
    std::vector<block> vec_K1 = PRG::GenRandomBlocks(seed, BASE_LEN);

    // Phase 1: first transmit 1-out-2 key to sender
    NPOT::PP pp_npot; 
    GetNPOTPP(pp, pp_npot); 
    NPOT::Send(io, pp_npot, vec_K0, vec_K1, BASE_LEN); 

    #ifdef DEBUG
        PrintSplitLine('*'); 
        std::cout << "1-sided IKNP OTE: receiver sends "<< BASE_LEN << " number of keys to sender via base OT" << std::endl; 
    #endif

    // generate the dense representation of selection block
    std::vector<block> vec_selection_block(ROW_NUM/128); 
    Block::FromSparseBits(vec_selection_bit.data(), ROW_NUM, vec_selection_block.data(), ROW_NUM/128); 


    // Phase 1: transmit ciphertext a.k.a. random shared matrix
    std::vector<block> vec_m0(ROW_NUM/128); 
    std::vector<block> vec_m1(ROW_NUM/128); 

    std::vector<block> vec_inner_C0(ROW_NUM/128); 
    std::vector<block> vec_inner_C1(ROW_NUM/128); 
    
    std::vector<block> vec_pad(ROW_NUM/128);
    // for every column: prepare two column vectors
    for(auto j = 0; j < COLUMN_NUM; j++)
    {
        // set vec_m0 be the jth column of T
        Block::FromDenseBits(T.data() + j*ROW_NUM/8, ROW_NUM, vec_m0.data(), ROW_NUM/128); 

        // set vec_m1 = vec_m0 xor selection_block
        vec_m1 = Block::XOR(vec_m0, vec_selection_block);

        PRG::ReSeed(seed, &vec_K0[j], 0); 
        vec_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        vec_inner_C0 = Block::XOR(vec_m0, vec_pad); 
        
        PRG::ReSeed(seed, &vec_K1[j], 0); 
        vec_pad = PRG::GenRandomBlocks(seed, ROW_NUM/128);
        vec_inner_C1 = Block::XOR(vec_m1, vec_pad);

        io.SendBlocks(vec_inner_C0.data(), ROW_NUM/128); 
        io.SendBlocks(vec_inner_C1.data(), ROW_NUM/128);
    }   

    #ifdef DEBUG
        std::cout << "1-sided IKNP OTE: receiver sends "<< COLUMN_NUM << " pair of ciphertexts to sender" << std::endl; 
    #endif
    
    std::vector<uint8_t> T_transpose(ROW_NUM/8 * COLUMN_NUM); 
    empBitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());

    #ifdef DEBUG
        std::cout << "1-sided IKNP OTE: receiver transposes matrix T" << std::endl; 
    #endif

    block outer_C; 
    
    #ifdef DEBUG
        std::cout << "1-sided IKNP OTE: receiver get "<< ROW_NUM << " number of ciphertexts from receiver" << std::endl; 
    #endif

    for(auto i = 0; i < ROW_NUM; i++)
    {
        io.ReceiveBlock(outer_C);
        std::vector<block> T_row_block(BASE_LEN/128);  
        Block::FromDenseBits(T_transpose.data()+i*COLUMN_NUM/8, BASE_LEN, T_row_block.data(), BASE_LEN/128); 
        
        // only decrypt when selection bit is 1
        if(vec_selection_bit[i] == 1){
            vec_result.push_back(outer_C^Hash::BlocksToBlock(T_row_block));
        }
    }   

    #ifdef DEBUG
        std::cout << "IKNP OTE: receiver obtains "<< ROW_NUM << " number of messages from receiver" << std::endl; 
        PrintSplitLine('*'); 
    #endif
}

}
#endif
