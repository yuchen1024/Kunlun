#ifndef KUNLUN_RRPKE_MQRPMT_HPP_
#define KUNLUN_RRPKE_MQRPMT_HPP_

#include "../../crypto/block.hpp"
#include "../../crypto/setup.hpp"
#include "../../netio/stream_channel.hpp"
#include "../../utility/serialization.hpp"
#include "../../crypto/ec_point.hpp"
#include "../../pke/elgamal.hpp"
#include "../okvs/baxos.hpp"

/** @file
*****************************************************************************
This is an implementation of multi-query leaky RPMT based on Rerandomizable PKE, mainly using ElGamal and OKVS::Baxos.

Note that the (ElGamal::CT) can be tansfered to (unsigned char [130]), as the efficient implementation of OKVS relys on block operations, we define BlockArrayValue(block[9]) to save the (ElGamal::CT).


 References:
 \[CYW+22]: 
 "Linear Private Set Union from Multi-Query Reverse Private Membership Test",
 Cong Zhang and Yu Chen and Weiran Liu and Min Zhang and Dongdai Lin, 
  USENIX Security 2023
 <https://eprint.iacr.org/2022/358>


 *****************************************************************************
 * @author     developed by Yujie Bai 
 *****************************************************************************/
namespace rrPKEmqRPMT{
    
using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    size_t statistical_security_parameter; // default=40 
    size_t LOG_SERVER_LEN; 
    size_t SERVER_LEN; 
    size_t LOG_CLIENT_LEN; 
    size_t CLIENT_LEN; 
};

// seriazlize
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{

    fout << pp.statistical_security_parameter; 
    fout << pp.LOG_SERVER_LEN;
    fout << pp.SERVER_LEN; 
    fout << pp.LOG_CLIENT_LEN;
    fout << pp.CLIENT_LEN; 

    return fout; 
}

// load pp from file
std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{

    fin >> pp.statistical_security_parameter; 

    fin >> pp.LOG_SERVER_LEN;
    fin >> pp.SERVER_LEN;
    fin >> pp.LOG_CLIENT_LEN;
    fin >> pp.CLIENT_LEN;

    return fin; 
}

PP Setup( size_t statistical_security_parameter, 
         size_t LOG_SERVER_LEN, 
         size_t LOG_CLIENT_LEN)
{
    PP pp; 
    pp.statistical_security_parameter = statistical_security_parameter; 
    pp.LOG_SERVER_LEN = LOG_SERVER_LEN; 
    pp.SERVER_LEN = size_t(pow(2, pp.LOG_SERVER_LEN)); 
    pp.LOG_CLIENT_LEN = LOG_CLIENT_LEN; 
    pp.CLIENT_LEN = size_t(pow(2, pp.LOG_CLIENT_LEN)); 
    return pp; 
}
void SavePP(PP &pp, std::string pp_filename)
{
    std::ofstream fout; 
    fout.open(pp_filename, std::ios::binary); 
    if(!fout){
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << pp; 
    fout.close(); 
}

void FetchPP(PP &pp, std::string pp_filename)
{
    std::ifstream fin; 
    fin.open(pp_filename, std::ios::binary); 
    if(!fin){
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }
    fin >> pp; 
    fin.close(); 
}
#ifndef ENABLE_X25519_ACCELERATION
BlockArrayValue CTtoBlockArrayValue(ElGamal::CT &ct){
    std::vector<unsigned char> ct_buffer(2*POINT_BYTE_LEN);   
    std::vector<unsigned char> refill_buffer(sizeof(BlockArrayValue),0);    
    ct_buffer = ElGamal::CTtoByteArray(ct);
    memcpy(refill_buffer.data(), ct_buffer.data(), 2*POINT_BYTE_LEN);
	return ((BlockArrayValue*)(&refill_buffer[0]))[0];
}

ElGamal::CT BlockArrayValueToCT(BlockArrayValue &BlockArrayValue){
 	std::vector<unsigned char> buffer(POINT_BYTE_LEN*2);
	memcpy(buffer.data(), &BlockArrayValue ,POINT_BYTE_LEN*2);
	ElGamal::CT ct = ElGamal::ByteArraytoCT(buffer);
	return ct;
}

std::vector<uint8_t> Server(NetIO &io, PP &pp, std::vector<block> &vec_Y){
 
    if(pp.SERVER_LEN != vec_Y.size()){
        std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
        exit(1);  
    }

    PrintSplitLine('-'); 
    
    auto start_time = std::chrono::steady_clock::now(); 
    
    // generate (sk,pk)
    BigInt sk; 
    ECPoint pk; // pk = g^sk
    ElGamal::PP pp_elgamal = ElGamal::Setup();
    std::tie(pk,sk) = ElGamal::KeyGen(pp_elgamal); 
    
    // send pk to client
    io.SendECPoint(pk);
    
    // pick a random m in group G    
    ECPoint m = GenRandomECPoint();
   
    // encrypt m SERVER_LEN times    
    std::vector<ElGamal::CT> ct(pp.SERVER_LEN);
    
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
        ct[i] = ElGamal::Enc(pp_elgamal, pk, m); // ct = [g^r, pk^r+m]
    } 
    
    uint64_t VALUE_BYTE_LEN = sizeof(BlockArrayValue);    
    
    // transfer CT[] to BlockArrayValue[]
    std::vector<BlockArrayValue> vec_value(pp.SERVER_LEN);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.SERVER_LEN; i++){
    	vec_value[i] = CTtoBlockArrayValue(ct[i]);
    }
            
    //encode(vec_y, vec_value) to get vec_out
    uint64_t bin_size = 1 << (pp.LOG_SERVER_LEN-7);
    Baxos<gf_128, BlockArrayValue> baxos(pp.SERVER_LEN, bin_size, 3, pp.statistical_security_parameter);
    auto out_length = baxos.bin_num * baxos.total_size;//calculate the output length of OKVS::decode(vec_Y,vec_out)
    std::vector<BlockArrayValue> vec_out(out_length);
    uint8_t baxos_thread_num = NUMBER_OF_THREADS;
    baxos.solve(vec_Y, vec_value, vec_out, 0, baxos_thread_num);
  
       
    //send the output of OKVS::decode to client
    io.SendBytes(vec_out.data(), out_length * VALUE_BYTE_LEN);
    
    //receive re-randomized ciphertext from client
    std::vector<BlockArrayValue> vec_rerand(pp.CLIENT_LEN);
    io.ReceiveBytes(vec_rerand.data(), pp.CLIENT_LEN * VALUE_BYTE_LEN);

    // decrypt the ciphertext and compare with initial m to get final output
    std::vector<uint8_t> vec_indication_bit(pp.CLIENT_LEN,0);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.CLIENT_LEN; i++){
    	ElGamal::CT ct = BlockArrayValueToCT(vec_rerand[i]);
    	ECPoint dec_m = ElGamal::Dec(pp_elgamal, sk, ct);
    	if(m == dec_m){
    		vec_indication_bit[i] = 1;
    	}    		
    }
    
    std::cout <<"rrPRF-based mqRPMT [step 1]: Server ===> [pk, Encode(y_i, z_i)--> D] ===> Client";
    std::cout << " [" << (double)VALUE_BYTE_LEN*out_length/(1024*1024) << " MB]" << std::endl;
   
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "rrPRF-based mqRPMT: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    
    PrintSplitLine('-'); 

    return vec_indication_bit; 
}

void Client(NetIO &io, PP &pp, std::vector<block> &vec_X) 
{    
    if(pp.CLIENT_LEN != vec_X.size()){
        std::cerr << "input size of vec_Y does not match public parameters" << std::endl;
        exit(1);  
    }
    
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 
    
    // receive pk from server
    ElGamal::PP pp_elgamal = ElGamal::Setup();
    ECPoint pk;
    io.ReceiveECPoint(pk);
    
    // calculate the output length and receive the out[]
    uint64_t bin_size = 1 << (pp.LOG_SERVER_LEN-7);
    Baxos<gf_128, BlockArrayValue> baxos(pp.SERVER_LEN, bin_size, 3, pp.statistical_security_parameter);
    auto out_length = baxos.bin_num * baxos.total_size;//calculate the output length of OKVS::decode(vec_Y,value_from_ct)
    std::vector<BlockArrayValue> vec_out(out_length);
    uint64_t VALUE_BYTE_LEN = sizeof(BlockArrayValue);
    io.ReceiveBytes(vec_out.data(), out_length * VALUE_BYTE_LEN);
    
    // decode vec_X with out[]
    std::vector<BlockArrayValue> vec_decode(pp.CLIENT_LEN);
    uint8_t thread_num = NUMBER_OF_THREADS;
    baxos.decode(vec_X, vec_decode, vec_out, thread_num);
    
    // re-rand the cipher and transfer it to BlockArrayValue
    std::vector<BlockArrayValue> vec_rerand(pp.CLIENT_LEN);
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < pp.CLIENT_LEN; ++i){
    	ElGamal::CT tmp_ct = BlockArrayValueToCT(vec_decode[i]);
    	ElGamal::CT new_ct = ElGamal::ReRand(pp_elgamal, pk, tmp_ct);
	vec_rerand[i] = CTtoBlockArrayValue(new_ct);
    }
    io.SendBytes(vec_rerand.data(), pp.CLIENT_LEN * VALUE_BYTE_LEN);
   

    std::cout <<"rrPKE-based mqRPMT [step 2]: Client ===> [pk, Re-Rand(decode(D,x_i),r)]===> Server"; 
    std::cout << " [" << (double)VALUE_BYTE_LEN*pp.CLIENT_LEN/(1024*1024) << " MB]" << std::endl;

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "rrPKE-based mqRPMT: Client side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-'); 
}

#endif

}
#endif
