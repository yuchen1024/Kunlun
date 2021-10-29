#ifndef KUNLUN_PSI_HPP_
#define KUNLUN_PSI_HPP_

#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/block.hpp"
#include "../netio/stream_channel.hpp"
#include "../ot/iknp_ote.hpp"

/*
** implement PSU based on weak commutative PSU
*/

namespace PSI{

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

void PipelineSender(NetIO &io, PP &pp, std::vector<block> &vec_X, size_t LEN) 
{
    // first act as sender in base OT
    BigInt k1 = GenRandomBigIntLessThan(order);

    std::vector<ECPoint> vec_Fk1k2_Y(LEN);
    ECPoint Fk2_Y;
    for(auto i = 0; i < LEN; i++){
        io.ReceiveECPoint(Fk2_Y);
        vec_Fk1k2_Y[i] = Fk2_Y * k1; 
    }

    // for(auto i = 0; i < LEN; i++){
    //     io.SendECPoint(vec_Fk1k2_Y[i]); 
    // }
    io.SendECPoints(vec_Fk1k2_Y.data(), LEN); 
    std::cout <<"DH-based PSI [step 2]: Sender ===> F_k1k2(y_i) ===> Receiver" << std::endl;
   
    ECPoint Fk1_X; 
    for(auto i = 0; i < LEN; i++){
        Fk1_X = Hash::BlockToECPoint(vec_X[i]) * k1; // H(y_i)^k2
        io.SendECPoint(Fk1_X); 
    }   
    std::cout <<"DH-based PSI [step 3]: Sender ===> F_k1(x_i) ===> Receiver" << std::endl;
}

     
void PipelineReceiver(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t LEN, std::unordered_set<std::string> &intersectionXY)
{
    // first act as sender in base OT
    BigInt k2 = GenRandomBigIntLessThan(order);
    ECPoint Fk2_Y;

    for(auto i = 0; i < LEN; i++){
        Fk2_Y = Hash::BlockToECPoint(vec_Y[i]) * k2; // H(y_i)^k2
        io.SendECPoint(Fk2_Y); 
    }
    
    std::cout <<"DH-based PSI [step 1]: Receiver ===> F_k2(y_i) ===> Sender" << std::endl;

    std::vector<ECPoint> vec_Fk1k2_Y(LEN); 
    // for(auto i = 0; i < LEN; i++){
    //     io.ReceiveECPoint(vec_Fk1k2_Y[i]); 
    // }
    io.ReceiveECPoints(vec_Fk1k2_Y.data(), LEN); 

    ECPoint Fk2k1_X, Fk1_X; 
    std::unordered_set<ECPoint, ECPointHash> S;
    for(auto i = 0; i < LEN; i++){ 
        io.ReceiveECPoint(Fk1_X); 
        Fk2k1_X = Fk1_X * k2; 
        S.insert(Fk2k1_X); 
    }

    for(auto i = 0; i < LEN; i++){
        if(S.find(vec_Fk1k2_Y[i]) != S.end()) 
            intersectionXY.insert(Block::ToString(vec_Y[i])); 
    }

    std::cout <<"DH-based PSI [step 4]: Receiver computes intersection(X, Y)" << std::endl;    
}


}

#endif
