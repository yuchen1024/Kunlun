#ifndef KUNLUN_OTP_HPP_
#define KUNLUN_OTP_HPP_

#include "prg.hpp"

inline void XOR(uint8_t* A, uint8_t* B, uint8_t* C, size_t LEN)
{
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){
        C[i] = A[i]^B[i]; 
    }    
}

inline std::string XOR(std::string &str_A, std::string &str_B)
{
    if(str_A.size() != str_B.size()){
        std::cerr << "size does not match" << std::endl; 
    }
    size_t LEN = str_A.size(); 
    std::string str_C(LEN, '0');
    XOR((uint8_t*)&str_A[0], (uint8_t*)&str_B[0], (uint8_t*)&str_C[0], LEN); 
    return str_C; 
}

inline std::vector<uint8_t> XOR(std::vector<uint8_t> &vec_A, std::vector<uint8_t> &vec_B)
{
    if(vec_A.size()!=vec_B.size()){
        std::cerr << "size does not match" << std::endl; 
    }
    size_t LEN = vec_A.size(); 
    std::vector<uint8_t> vec_C(LEN);
    XOR((uint8_t*)&vec_A[0], &vec_B[0], &vec_C[0], LEN); 
    return vec_C; 
}


namespace OTP{

std::vector<uint8_t> Enc(block &key, std::vector<uint8_t>& plaintext)
{
    size_t LEN = plaintext.size(); 
    PRG::Seed seed = PRG::SetSeed(&key, 0);
    std::vector<uint8_t> one_time_pad = PRG::GenRandomBytes(seed, LEN); 
    std::vector<uint8_t> ciphertext = XOR(one_time_pad, plaintext); 
    return ciphertext; 
}

std::vector<uint8_t> Dec(block &key, std::vector<uint8_t>& ciphertext)
{
    size_t LEN = ciphertext.size(); 
    PRG::Seed seed = PRG::SetSeed(&key, 0);
    std::vector<uint8_t> one_time_pad = PRG::GenRandomBytes(seed, LEN); 
    std::vector<uint8_t> plaintext = XOR(one_time_pad, ciphertext); 
    return plaintext; 
}

std::string Enc(block &key, std::string& str_plaintext)
{
    size_t LEN = str_plaintext.size(); 
    std::vector<uint8_t> plaintext(LEN); 
    memcpy(&plaintext[0], str_plaintext.data(), LEN); 
    std::vector<uint8_t> ciphertext = Enc(key, plaintext); 
    std::string str_ciphertext(LEN, '0'); 
    memcpy(&str_ciphertext[0], ciphertext.data(), LEN); 
    return str_ciphertext; 
}

std::string Dec(block &key, std::string& str_ciphertext)
{
    size_t LEN = str_ciphertext.size(); 
    std::vector<uint8_t> ciphertext(LEN); 
    memcpy(&ciphertext[0], str_ciphertext.data(), LEN); 
    std::vector<uint8_t> plaintext = Enc(key, ciphertext); 
    std::string str_plaintext(LEN, '0'); 
    memcpy(&str_plaintext[0], plaintext.data(), LEN); 
    return str_plaintext; 
}

}




#endif// PRP_H__




