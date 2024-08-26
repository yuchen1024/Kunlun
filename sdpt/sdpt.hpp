/****************************************************************************
this hpp implements the SDPT functionality 
*****************************************************************************/
#ifndef SDPT_HPP_
#define SDPT_HPP_

#include "../pke/exponential_elgamal.hpp"        // implement ElGamal  
#include "../pke/elgamal.hpp"  
#include "../zkp/bulletproofs/sigma_bullet_proof.hpp"    // implement Log Size Bulletproof
#include "../zkp/nizk/nizk_many_out_of_many.hpp" // implement many out of many proof
#include "../zkp/nizk/nizk_plaintext_bit_equality.hpp" // implement Supervise knowledge proof
#include "../zkp/nizk/nizk_multi_plaintext_equality.hpp" // implement Supervise knowledge proof

#include "../gadget/range_proof.hpp"
#include "../utility/serialization.hpp"

#include <time.h>
#define DEMO           // demo mode 
//#define DEBUG        // show debug information 


namespace SDPT{

using Serialization::operator<<; 
using Serialization::operator>>; 


// define the structure of system parameters

struct PP{    
    BigInt MAXIMUM_COINS; 
    size_t AnonSetNum; // the number of AnonSet,include the sender
    SigmaBullet::PP sigmabullet_part;
    ExponentialElGamal::PP enc_part;
    // ElGamal::PP enc_part_nexp;
    Pedersen::PP com_part;
    ECPoint pka; // supervisor's pk
};

// define the structure of system parameters
struct SP{
    BigInt ska;   // supervisor's sk
};

struct Account{
    std::string identity;     // id
    ECPoint pk;              // public key
    BigInt sk;              // secret key
    ExponentialElGamal::CT balance_ct;  // current balance
    BigInt m;               // dangerous (should only be used for speeding up the proof generation)
    //BigInt sn; ..remove sn
};

struct AnonSet{
    std::string identity;
    ECPoint pk;
    ExponentialElGamal::CT balance_act; // current balance
};

struct SuperviseResult
{
    BigInt value_cipher_supervison;
    size_t Supervise_sender_index;
    size_t Supervise_receiver_index;
    ECPoint sender_pk;
    ECPoint receiver_pk;
};

//the structure of Anonymous Transaction 1
struct StofAnoyTransaction1{
   BigInt epnumber; // the number of epoch
   ECPoint gepoch; // the generator of epoch
   ECPoint uepoch;// uepoch=gepoch^sender_sk
   size_t number; // the number of AnonSet+sender + receiver
   size_t Log_number; // the index of sender
   std::vector<std::string> identity; // the identity of AnonSet+sender + receiver;

   std::vector<ECPoint> pk; // the pk of AnonSet+sender + receiver;
   std::vector<ExponentialElGamal::CT> balance_act; // the balance of AnonSet+sender + receiver;
   std::vector<ExponentialElGamal::CT> transfer_ct; // the transfer of AnonSet+sender + receiver;

   //validity proof
   ManyOutOfMany::Proof proof_many_out_of_many_proof; // NIZKPoK for the validity of tx
    
   SigmaBullet::Proof proof_sigma_bullet_proof; // NIZKPoK for the validity of tx
   
   ExponentialElGamal::CT value_cipher_supervison;
   std::vector<ExponentialElGamal::CT>Supervise_indexl0;
   std::vector<ExponentialElGamal::CT>Supervise_indexl1;
   //Superviseable proof
   PlaintextBitEquality::Proof proof_Supervise_knowledge1_proof; // NIZKPoK for the Superviseable of tx

};

//the structure of Anonymous Transaction 2
struct StofAnoyTransaction2{
   BigInt epnumber; // the number of epoch
   ECPoint gepoch; // the generator of epoch
   ECPoint uepoch;// uepoch=gepoch^sender_sk
   size_t number; // the number of AnonSet+sender + receiver
   size_t Log_number; // the index of sender
   std::vector<std::string> identity; // the identity of AnonSet+sender + receiver;

   std::vector<ECPoint> pk; // the pk of AnonSet+sender + receiver;
   std::vector<ExponentialElGamal::CT> balance_act; // the balance of AnonSet+sender + receiver;
   std::vector<ExponentialElGamal::CT> transfer_ct; // the transfer of AnonSet+sender + receiver;

   //validity proof
   ManyOutOfMany::Proof proof_many_out_of_many_proof; // NIZKPoK for the validity of tx
    
   SigmaBullet::Proof proof_sigma_bullet_proof; // NIZKPoK for the validity of tx
   
   std::vector<ExponentialElGamal::CT>Supervise_ct;
   //Superviseable proof
   MultiPlaintextEquality::Proof proof_Supervise_knowledge2_proof; // NIZKPoK for the Superviseable of tx

};
std::string GetAnoyTxFileName(StofAnoyTransaction1 &AnoyTransaction)
{
    std::string tx_file="Anonytx_way1_"+AnoyTransaction.epnumber.ToHexString()+".tx";    
    return tx_file; 
}
std::string GetAnoyTxFileName(StofAnoyTransaction2 &AnoyTransaction)
{
    std::string tx_file="Anonytx_way2_"+AnoyTransaction.epnumber.ToHexString()+".tx";    
    return tx_file; 
}
void PrintPP(PP &pp)
{
    PrintSplitLine('-');
    std::cout << "pp content >>>>>>" << std::endl; 
    std::cout << "AnonSetNum = " << pp.AnonSetNum << std::endl; 

    pp.pka.Print("supervisor's pk"); 
    
    PrintSplitLine('-'); 
}

void PrintAccount(Account &Acct)
{
    std::cout << Acct.identity << " account information >>> " << std::endl;     
    Acct.pk.Print("pk"); 
    std::cout << "encrypted balance:" << std::endl; 
    ExponentialElGamal::PrintCT(Acct.balance_ct);  // current balance
    Acct.m.PrintInDec("m"); 
    PrintSplitLine('-'); 
}

void PrintAnonyTX1(StofAnoyTransaction1 &AnoyTransaction)
{
    PrintSplitLine('-');
    std::string tx_file = GetAnoyTxFileName(AnoyTransaction);  
    std::cout << tx_file << " content >>>>>>" << std::endl; 

    std::cout << "epoch number >>>" << std::endl; 
    AnoyTransaction.epnumber.Print("epoch number"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    AnoyTransaction.gepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    AnoyTransaction.uepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "number of participants >>>" << AnoyTransaction.number << std::endl; 
    std::cout << "Log_number of participants >>>" << AnoyTransaction.Log_number << std::endl; 

    std::cout << "participants' identity >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        std::cout << AnoyTransaction.identity[i] << std::endl; 
    }
    std::cout << std::endl; 

    std::cout << "participants' pk >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        AnoyTransaction.pk[i].Print("pk"); 
    }
    std::cout << std::endl; 

    std::cout << "participants' balance >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        ExponentialElGamal::PrintCT(AnoyTransaction.balance_act[i]); 
    }
    std::cout << std::endl; 

    std::cout << "participants' transfer >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        ExponentialElGamal::PrintCT(AnoyTransaction.transfer_ct[i]); 
    }
    std::cout << std::endl; 

    std::cout << "NIZKPoK for valid  >>>" << std::endl; 
    ManyOutOfMany::PrintProof(AnoyTransaction.proof_many_out_of_many_proof);
    std::cout << std::endl;

    //the encryption of value_cipher_supervison is not print

    std::cout << "NIZKPoK for Supervise 1 >>>" << std::endl;
    PlaintextBitEquality::PrintProof(AnoyTransaction.proof_Supervise_knowledge1_proof);
    std::cout << std::endl;

}

void PrintAnonyTX2(StofAnoyTransaction2 &AnoyTransaction)
{
    PrintSplitLine('-');
    std::string tx_file = GetAnoyTxFileName(AnoyTransaction);  
    std::cout << tx_file << " content >>>>>>" << std::endl; 

    std::cout << "epoch number >>>" << std::endl; 
    AnoyTransaction.epnumber.Print("epoch number"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    AnoyTransaction.gepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    AnoyTransaction.uepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "number of participants >>>" << AnoyTransaction.number << std::endl; 
    std::cout << "Log_number of participants >>>" << AnoyTransaction.Log_number << std::endl; 

    std::cout << "participants' identity >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        std::cout << AnoyTransaction.identity[i] << std::endl; 
    }
    std::cout << std::endl; 

    std::cout << "participants' pk >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        AnoyTransaction.pk[i].Print("pk"); 
    }
    std::cout << std::endl; 

    std::cout << "participants' balance >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        ExponentialElGamal::PrintCT(AnoyTransaction.balance_act[i]); 
    }
    std::cout << std::endl; 

    std::cout << "participants' transfer >>>" << std::endl; 
    for(size_t i = 0; i < AnoyTransaction.number; i++){
        ExponentialElGamal::PrintCT(AnoyTransaction.transfer_ct[i]); 
    }
    std::cout << std::endl; 

    std::cout << "NIZKPoK for valid  >>>" << std::endl; 
    ManyOutOfMany::PrintProof(AnoyTransaction.proof_many_out_of_many_proof);
    std::cout << std::endl;

    std::cout << "NIZKPoK for Supervise 2 >>>" << std::endl;
    MultiPlaintextEquality::PrintProof(AnoyTransaction.proof_Supervise_knowledge2_proof);
    std::cout << std::endl;
}

void SaveSP(SP &sp, std::string SDPT_SP_File)
{
    std::ofstream fout;
    fout.open(SDPT_SP_File, std::ios::binary); 
    fout << sp.ska;
    fout.close();   
}

void FetchSP(SP &sp, std::string SDPT_SP_File)
{
    std::ifstream fin; 
    fin.open(SDPT_SP_File, std::ios::binary); 
    fin >> sp.ska; 
    fin.close();   
}

void SavePP(PP &pp, std::string SDPT_PP_File)
{
    std::ofstream fout; 
    fout.open(SDPT_PP_File, std::ios::binary); 

    fout << pp.MAXIMUM_COINS; 
    fout << pp.AnonSetNum;
    fout << pp.pka; 

    fout << pp.sigmabullet_part; 
    fout << pp.enc_part; 
    fout << pp.com_part;

    fout.close();   
}

void FetchPP(PP &pp, std::string SDPT_PP_File)
{
    std::ifstream fin; 
    fin.open(SDPT_PP_File, std::ios::binary); 

    fin >> pp.MAXIMUM_COINS;  
    fin >> pp.AnonSetNum;
    fin >> pp.pka; 
 
    fin >> pp.sigmabullet_part;
    fin >> pp.enc_part; 
    fin >> pp.com_part;

    fin.close();   
}

void SaveAccount(Account &user, std::string SDPT_Account_File)
{
    std::ofstream fout; 
    fout.open(SDPT_Account_File, std::ios::binary);
    fout << user.identity;  
    fout << user.pk;              
    fout << user.sk;   
    fout << user.balance_ct;  
    fout << user.m; 
    fout.close();  
}

void FetchAccount(Account &user, std::string SDPT_Account_File)
{
    std::ifstream fin; 
    fin.open(SDPT_Account_File, std::ios::binary);
    fin >> user.identity; 
    fin >> user.pk;              
    fin >> user.sk;             
    fin >> user.balance_ct;
    fin >> user.m; 
    fin.close();  
}

void SaveAnonyTx1(StofAnoyTransaction1 AnoyTransaction,std::string SDPT_AnonyTx_File)
{
    std::ofstream fout; 
    fout.open(SDPT_AnonyTx_File, std::ios::binary); 
    
    fout << AnoyTransaction.epnumber;
    fout << AnoyTransaction.gepoch;
    fout << AnoyTransaction.uepoch;
    size_t number=AnoyTransaction.number;
    for(auto i=0;i<number;i++)
    {
        fout << AnoyTransaction.identity[i];
        fout << AnoyTransaction.pk[i];
        fout << AnoyTransaction.balance_act[i];
        fout << AnoyTransaction.transfer_ct[i];
    }
    // save proofs
    fout << AnoyTransaction.proof_many_out_of_many_proof;
    //save supertvisor's Supervise1 result and proof
    fout << AnoyTransaction.value_cipher_supervison;
    for(auto i=0;i<AnoyTransaction.Supervise_indexl0.size();i++){
        fout << AnoyTransaction.Supervise_indexl0[i];
    }
    for(auto i=0;i<AnoyTransaction.Supervise_indexl1.size();i++){
        fout << AnoyTransaction.Supervise_indexl1[i];
    }
    fout << AnoyTransaction.proof_Supervise_knowledge1_proof;
    
    fout.close();
    //to do list: the thrid way to Supervise the transaction

    // calculate the size of tx_file
    std::ifstream fin; 
    fin.open(SDPT_AnonyTx_File, std::ios::ate | std::ios::binary);
    std::cout << SDPT_AnonyTx_File << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
    return;
}

void SaveAnonyTx2(StofAnoyTransaction2 AnoyTransaction,std::string SDPT_AnonyTx_File)
{
    std::ofstream fout; 
    fout.open(SDPT_AnonyTx_File, std::ios::binary); 
    
    fout << AnoyTransaction.epnumber;
    fout << AnoyTransaction.gepoch;
    fout << AnoyTransaction.uepoch;
    size_t number=AnoyTransaction.number;
    for(auto i=0;i<number;i++)
    {
        fout << AnoyTransaction.identity[i];
        fout << AnoyTransaction.pk[i];
        fout << AnoyTransaction.balance_act[i];
        fout << AnoyTransaction.transfer_ct[i];
    }
    // save proofs
    fout << AnoyTransaction.proof_many_out_of_many_proof;
    
    //save supertvisor's Supervise2 result and proof
    for(auto i=0;i<AnoyTransaction.Supervise_ct.size();i++){
        fout << AnoyTransaction.Supervise_ct[i];
    }
    fout << AnoyTransaction.proof_Supervise_knowledge2_proof;
    fout.close();
    //to do list: the thrid way to Supervise the transaction

    // calculate the size of tx_file
    std::ifstream fin; 
    fin.open(SDPT_AnonyTx_File, std::ios::ate | std::ios::binary);
    std::cout << SDPT_AnonyTx_File << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
    return;
}

void FetchAnonyTx1(StofAnoyTransaction1 &AnoyTransaction, std::string SDPT_AnonyTx_File)
{
    // Deserialize_AnonyTx(AnoyTransaction, tx_file); 
    std::ifstream fin; 
    fin.open(SDPT_AnonyTx_File);

    // recover 
    fin >> AnoyTransaction.epnumber;
    fin >> AnoyTransaction.gepoch;
    fin >> AnoyTransaction.uepoch;
    size_t number=AnoyTransaction.number;
    for(auto i=0;i<number;i++)
    {
        fin >> AnoyTransaction.identity[i];
        fin >> AnoyTransaction.pk[i];
        fin >> AnoyTransaction.balance_act[i];
        fin >> AnoyTransaction.transfer_ct[i];
    }
    // recover proof
    fin >> AnoyTransaction.proof_many_out_of_many_proof;
    //recover supertvisor's Supervise1 result and proof
    fin >> AnoyTransaction.value_cipher_supervison;
    for(auto i=0;i<AnoyTransaction.Supervise_indexl0.size();i++){
        fin >> AnoyTransaction.Supervise_indexl0[i];
    }
    for(auto i=0;i<AnoyTransaction.Supervise_indexl1.size();i++){
        fin >> AnoyTransaction.Supervise_indexl1[i];
    }
    fin >> AnoyTransaction.proof_Supervise_knowledge1_proof;
   
    fin.close(); 
}

void FetchAnonyTx2(StofAnoyTransaction2 &AnoyTransaction, std::string SDPT_AnonyTx_File)
{
    // Deserialize_AnonyTx(AnoyTransaction, tx_file); 
    std::ifstream fin; 
    fin.open(SDPT_AnonyTx_File);

    // recover 
    fin >> AnoyTransaction.epnumber;
    fin >> AnoyTransaction.gepoch;
    fin >> AnoyTransaction.uepoch;
    size_t number=AnoyTransaction.number;
    for(auto i=0;i<number;i++)
    {
        fin >> AnoyTransaction.identity[i];
        fin >> AnoyTransaction.pk[i];
        fin >> AnoyTransaction.balance_act[i];
        fin >> AnoyTransaction.transfer_ct[i];
    }
    // recover proof
    fin >> AnoyTransaction.proof_many_out_of_many_proof;
    
    //recover supertvisor's Supervise2 result and proof
    for(auto i=0;i<AnoyTransaction.Supervise_ct.size();i++){
        fin >> AnoyTransaction.Supervise_ct[i];
    }
    fin >> AnoyTransaction.proof_Supervise_knowledge2_proof;
    fin.close(); 
}

/* This function implements Setup algorithm of SDPT */
std::tuple<PP, SP> Setup(size_t LOG_MAXIMUM_COINS, size_t AnonSetNum)
{
    PP pp; 
    SP sp; 

    if(IsPowerOfTwo(AnonSetNum) == false){ 
        std::cout << "parameters warning: (AnonSetNum) had better be a power of 2" << std::endl;
    }
     
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, LOG_MAXIMUM_COINS)));  
    pp.AnonSetNum = AnonSetNum;

    size_t MAX_AGG_NUM = AnonSetNum ;
    size_t Log_AnonSetNum = size_t(log2(AnonSetNum-1)+1);
    std::cout << "MAX_AGG_NUM = " << MAX_AGG_NUM << std::endl;
    std::cout << "Log_AnonSetNum = " << Log_AnonSetNum << std::endl;
    pp.sigmabullet_part = SigmaBullet::Setup(LOG_MAXIMUM_COINS, MAX_AGG_NUM); 
    
    size_t TRADEOFF_NUM = 7; 
    pp.enc_part = ExponentialElGamal::Setup(LOG_MAXIMUM_COINS, TRADEOFF_NUM);  
    pp.com_part = Pedersen::Setup(4*Log_AnonSetNum+2); // the size of the Pedersen commitment is 4*Log_AnonSetNum+2

    std::tie(pp.pka, sp.ska) = ExponentialElGamal::KeyGen(pp.enc_part);

    return {pp, sp};
}

/* initialize the encryption part for faster decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize SDPT >>>" << std::endl;  
    ExponentialElGamal::Initialize(pp.enc_part); 
    PrintSplitLine('-'); 
}

/* create an account for input identity */
Account CreateAccount(PP &pp, std::string identity, BigInt &init_balance)
{
    Account newAcct;
    newAcct.identity = identity;


    std::tie(newAcct.pk, newAcct.sk) = ExponentialElGamal::KeyGen(pp.enc_part); // generate a keypair

    newAcct.m = init_balance; 

    // initialize account balance with 0 coins
    BigInt r = Hash::StringToBigInt(newAcct.identity); 
    newAcct.balance_ct = ExponentialElGamal::Enc(pp.enc_part, newAcct.pk, init_balance, r);

    #ifdef DEMO
        std::cout << identity << "'s SDPT account creation succeeds" << std::endl;
        newAcct.pk.Print("pk"); 
        std::cout << identity << "'s initial balance = "; 
        newAcct.m.PrintInDec(); 
        std::cout << std::endl;
        PrintSplitLine('-'); 
    #endif 

    return newAcct;
}

/* reveal the balance */ 
BigInt RevealBalance(PP &pp, Account &Acct)
{
    return ExponentialElGamal::Dec(pp.enc_part, Acct.sk, Acct.balance_ct); 
}

// generate a random number(not really random) from 0 to n-1 (n is the number of AnonSet)
size_t getranindex(size_t n)
{
    srand(time(0));
    return rand() % n;
}
// create a anonymous transaction: pk1 transfers v coins to pk2
StofAnoyTransaction1 CreateAnoyTransaction1(PP &pp, Account &Acct_sender, BigInt &v, std::vector<AnonSet> &AnonSetList, ECPoint &pkr,BigInt epnumber,size_t sender_index,size_t receiver_index)
{
    StofAnoyTransaction1 AnoyTransaction;
    AnoyTransaction.number = AnonSetList.size();
    AnoyTransaction.Log_number =size_t(log2(AnoyTransaction.number-1)+1); 
    PrintSplitLine('-');
    std::cout<<"the number of AnonSet is "<<AnoyTransaction.number<<std::endl;
    std::cout<<"the Log_number of AnonSet is "<<AnoyTransaction.Log_number<<std::endl;

    
    std::vector<std::string> identity_list(AnoyTransaction.number);
    std::vector<ECPoint> pk_list(AnoyTransaction.number);
    std::vector<ExponentialElGamal::CT> balance_act_list(AnoyTransaction.number);
    std::vector<ExponentialElGamal::CT> transfer_ct_list(AnoyTransaction.number);

    auto start_time = std::chrono::steady_clock::now();
    /*fill the struct of vec */
    for(size_t i=0;i<AnoyTransaction.number;i++)
    {
        identity_list[i] = AnonSetList[i].identity;
        pk_list[i] = AnonSetList[i].pk;
        balance_act_list[i] = AnonSetList[i].balance_act;
    }
    /*fill the struct of sender  */
    BigInt r = GenRandomBigIntLessThan(order); // the random r will be reused

    //we need to choose another way to generate the random r to prepare for the Supervise way 3 later
   
    transfer_ct_list[sender_index] = ExponentialElGamal::Enc(pp.enc_part, Acct_sender.pk, -v, r); // transfer -v coins to receiver

 
    transfer_ct_list[receiver_index] = ExponentialElGamal::Enc(pp.enc_part, pkr, v, r); // transfer v coins to receiver
 
    for(auto i=0;i<AnoyTransaction.number;i++)
    {
        if(i!=sender_index && i!=receiver_index){
            transfer_ct_list[i] = ExponentialElGamal::Enc(pp.enc_part, AnonSetList[i].pk, bn_0, r); // transfer 0 coins to AnonSet
        }
    }
    
    AnoyTransaction.epnumber = epnumber;
    AnoyTransaction.gepoch=Hash::StringToECPoint("SDPT"+epnumber.ToHexString());
    AnoyTransaction.uepoch=AnoyTransaction.gepoch*Acct_sender.sk;
    AnoyTransaction.identity = identity_list;
    AnoyTransaction.pk = pk_list;
    AnoyTransaction.balance_act = balance_act_list;
    AnoyTransaction.transfer_ct = transfer_ct_list;
    PrintSplitLine('-');
    std::cout << "successfully fill the struct of AnoyTransaction" << std::endl;
    std::string transcript_str = "";
    //begin to generate NIZK proof for validity of tx
    PrintSplitLine('-');
    std::cout << "begin to generate NIZK proof for validity of tx" << std::endl;
    
    ManyOutOfMany::PP many_out_of_many_pp;
    many_out_of_many_pp= ManyOutOfMany::Setup(AnoyTransaction.number,AnoyTransaction.Log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout<<"successfully setup the ManyOutOfMany Proof"<<std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;

    many_out_of_many_instance.vec_pk=AnoyTransaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(AnoyTransaction.number);
    
    for(size_t i=0;i<AnoyTransaction.number;i++)
    {
        many_out_of_many_instance.vec_cipher_balance_left[i] = AnoyTransaction.balance_act[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = AnoyTransaction.balance_act[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = AnoyTransaction.transfer_ct[i].Y;
    }
    many_out_of_many_instance.cipher_transfer_right =AnoyTransaction.transfer_ct[0].X;
    
    many_out_of_many_instance.gepoch=AnoyTransaction.gepoch;
    many_out_of_many_instance.uepoch=AnoyTransaction.uepoch;


    /*Home add */
    for(size_t i=0;i<AnoyTransaction.number;i++){
       AnoyTransaction.balance_act[i]=ExponentialElGamal::HomoAdd(AnoyTransaction.balance_act[i],
                                                            AnoyTransaction.transfer_ct[i]); 
       many_out_of_many_instance.vec_cipher_balance_left[i] = AnoyTransaction.balance_act[i].Y;
       many_out_of_many_instance.vec_cipher_balance_right[i] = AnoyTransaction.balance_act[i].X;                                                    
    }
    PrintSplitLine('-');
    std::cout<<"successfully fill the instance of the proof"<<std::endl;
    ManyOutOfMany::Witness many_out_of_many_witness;

    many_out_of_many_witness.sender_index=sender_index;
    many_out_of_many_witness.receiver_index=receiver_index;
    many_out_of_many_witness.value=v;
    many_out_of_many_witness.r=r;
    many_out_of_many_witness.sk=Acct_sender.sk;
    PrintSplitLine('-');
    std::cout<<"begin to decrypt the balance of the sender"<<std::endl;
    many_out_of_many_witness.vprime=ExponentialElGamal::Dec(pp.enc_part,Acct_sender.sk,
                                    AnoyTransaction.balance_act[sender_index]);
    PrintSplitLine('-');
    std::cout<<"successfully decrypt the balance of the sender"<<std::endl;
   
    // vprime = sender's balance-transfer value
    size_t vprime_size_t=many_out_of_many_witness.vprime.ToUint64();
    //PrintSplitLine('-');
    //std::cout<<"vprime_size_t="<<vprime_size_t<<std::endl;

    ManyOutOfMany::ConsRandom cons_random;
    ManyOutOfMany::Proof proof_many_out_of_many_proof;

    PrintSplitLine('-');
    std::cout<<"begin to prove the validity of the transaction"<<std::endl;
    ManyOutOfMany::Prove(many_out_of_many_pp, many_out_of_many_witness,many_out_of_many_instance,
                 transcript_str,proof_many_out_of_many_proof,cons_random);

    AnoyTransaction.proof_many_out_of_many_proof = proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout<<"successfully generate the NIZK proof for validity of tx"<<std::endl;

    SigmaBullet::Instance sigmabullet_instance;
    SigmaBullet::Witness sigmabullet_witness;
    SigmaBullet::Proof proof_sigma_bullet_proof;
    sigmabullet_instance.cipher_transfer_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_right.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        sigmabullet_instance.cipher_transfer_left[i]=AnoyTransaction.transfer_ct[i].Y;
        sigmabullet_instance.cipher_transfer_right[i]=AnoyTransaction.transfer_ct[i].X;
    }
    for(size_t i=0;i<AnoyTransaction.number;i++){
        sigmabullet_instance.cipher_balance_left[i]=AnoyTransaction.balance_act[i].Y;
        sigmabullet_instance.cipher_balance_left[i]=AnoyTransaction.balance_act[i].X;
    }
    sigmabullet_witness.v={v,many_out_of_many_witness.vprime};
    transcript_str="";
    PrintSplitLine('-');
    std::cout<<"begin to prove the sigma bullet proof"<<std::endl;
    SigmaBullet::Prove(pp.sigmabullet_part,sigmabullet_instance,sigmabullet_witness,
                transcript_str,proof_sigma_bullet_proof,cons_random,proof_many_out_of_many_proof);
    PrintSplitLine('-');
    std::cout<<"successfully generate the sigma bullet proof"<<std::endl;
    AnoyTransaction.proof_sigma_bullet_proof = proof_sigma_bullet_proof;

    //the way 1

    PlaintextBitEquality::PP plaintext_bit_equality_pp = PlaintextBitEquality::Setup(pp.enc_part,AnoyTransaction.number,pp.pka);
    PrintSplitLine('-');
    std::cout<<"successfully setup the PlaintextBitEquality Proof"<<std::endl;
    PlaintextBitEquality::Instance plaintext_bit_equality_instance;
    PlaintextBitEquality::Witness plaintext_bit_equality_witness;
    plaintext_bit_equality_witness.v=v;
    plaintext_bit_equality_instance.vec_cipher_transfer.resize(AnoyTransaction.number);
    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_v.resize(AnoyTransaction.Log_number);
    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_v.resize(AnoyTransaction.Log_number);
    plaintext_bit_equality_instance.vec_pk=AnoyTransaction.pk;
    for(size_t i=0;i<AnoyTransaction.number;i++){
        plaintext_bit_equality_instance.vec_cipher_transfer[i]=AnoyTransaction.transfer_ct[i];
    }
    BigInt cipher_supervison_value_r=GenRandomBigIntLessThan(order);
    plaintext_bit_equality_witness.cipher_supervison_value_r=cipher_supervison_value_r;
    AnoyTransaction.value_cipher_supervison=ExponentialElGamal::Enc(pp.enc_part,pp.pka,v,cipher_supervison_value_r);
    plaintext_bit_equality_instance.value_cipher_supervison=AnoyTransaction.value_cipher_supervison;

    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_r.resize(AnoyTransaction.Log_number);
    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_r.resize(AnoyTransaction.Log_number);
    AnoyTransaction.Supervise_indexl0.resize(AnoyTransaction.Log_number);
    AnoyTransaction.Supervise_indexl1.resize(AnoyTransaction.Log_number);
    BigInt Supervise_indexl0_r;
    BigInt Supervise_indexl1_r;
    BigInt Supervise_indexl0_v;
    BigInt Supervise_indexl1_v;
    PrintSplitLine('-');
    std::cout<<"begin to generate the vector index"<<std::endl;

    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_sender.resize(AnoyTransaction.Log_number);
    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_receiver.resize(AnoyTransaction.Log_number);
    for(size_t i=0;i<AnoyTransaction.Log_number;i++){
        Supervise_indexl0_r=GenRandomBigIntLessThan(order);
        Supervise_indexl1_r=GenRandomBigIntLessThan(order);
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_r[i]=Supervise_indexl0_r;
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_r[i]=Supervise_indexl1_r;

        if((sender_index>>i)&1==1)
        {
            Supervise_indexl0_v=bn_1;
        }
        else
        {
            Supervise_indexl0_v=bn_0;
        }
        if((receiver_index>>i)&1==1)
        {
            Supervise_indexl1_v=bn_1;
        }
        else
        {
            Supervise_indexl1_v=bn_0;
        }

        AnoyTransaction.Supervise_indexl0[i]=ExponentialElGamal::Enc(pp.enc_part,pp.pka,Supervise_indexl0_v,Supervise_indexl0_r);
        AnoyTransaction.Supervise_indexl1[i]=ExponentialElGamal::Enc(pp.enc_part,pp.pka,Supervise_indexl1_v,Supervise_indexl1_r);
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_v[i]=Supervise_indexl0_v;
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_v[i]=Supervise_indexl1_v;
        plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_sender[i]=AnoyTransaction.Supervise_indexl0[i];
        plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_receiver[i]=AnoyTransaction.Supervise_indexl1[i];
    }
    std::string transcript_Supervise_str1 = "";
    PrintSplitLine('-');
    std::cout<<"begin to prove the Supervise knowledge1"<<std::endl;
    AnoyTransaction.proof_Supervise_knowledge1_proof = PlaintextBitEquality::Prove(plaintext_bit_equality_pp, plaintext_bit_equality_instance, 
                            plaintext_bit_equality_witness,AnoyTransaction.proof_many_out_of_many_proof,transcript_Supervise_str1,cons_random);

    PrintSplitLine('-');
    std::cout<<"successfully generate the Supervise knowledge1 proof"<<std::endl;
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "AnoyTransaction generation1 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    return AnoyTransaction;
}

// create a anonymous transaction2: pk1 transfers v coins to pk2
StofAnoyTransaction2 CreateAnoyTransaction2(PP &pp, Account &Acct_sender, BigInt &v, std::vector<AnonSet> &AnonSetList, ECPoint &pkr,BigInt epnumber,size_t sender_index,size_t receiver_index)
{
    
    StofAnoyTransaction2 AnoyTransaction;
    AnoyTransaction.number = AnonSetList.size();
    AnoyTransaction.Log_number =size_t(log2(AnoyTransaction.number-1)+1); 
    PrintSplitLine('-');
    std::cout<<"the number of AnonSet is "<<AnoyTransaction.number<<std::endl;
    std::cout<<"the Log_number of AnonSet is "<<AnoyTransaction.Log_number<<std::endl;

    std::vector<std::string> identity_list(AnoyTransaction.number);
    std::vector<ECPoint> pk_list(AnoyTransaction.number);
    std::vector<ExponentialElGamal::CT> balance_act_list(AnoyTransaction.number);
    std::vector<ExponentialElGamal::CT> transfer_ct_list(AnoyTransaction.number);

    auto start_time = std::chrono::steady_clock::now();
    /*fill the struct of vec */
    for(size_t i=0;i<AnoyTransaction.number;i++)
    {
        identity_list[i] = AnonSetList[i].identity;
        pk_list[i] = AnonSetList[i].pk;
        balance_act_list[i] = AnonSetList[i].balance_act;
    }
    /*fill the struct of sender  */
    BigInt r = GenRandomBigIntLessThan(order); // the random r will be reused
    
    transfer_ct_list[sender_index] = ExponentialElGamal::Enc(pp.enc_part, Acct_sender.pk, -v, r); // transfer -v coins to receiver

 
    transfer_ct_list[receiver_index] = ExponentialElGamal::Enc(pp.enc_part, pkr, v, r); // transfer v coins to receiver
 
    for(auto i=0;i<AnoyTransaction.number;i++)
    {
        if(i!=sender_index && i!=receiver_index){
            transfer_ct_list[i] = ExponentialElGamal::Enc(pp.enc_part, AnonSetList[i].pk, bn_0, r); // transfer 0 coins to AnonSet
        }
    }
    
    AnoyTransaction.epnumber = epnumber;
    AnoyTransaction.gepoch=Hash::StringToECPoint("SDPT"+epnumber.ToHexString());
    AnoyTransaction.uepoch=AnoyTransaction.gepoch*Acct_sender.sk;
    AnoyTransaction.identity = identity_list;
    AnoyTransaction.pk = pk_list;
    AnoyTransaction.balance_act = balance_act_list;
    AnoyTransaction.transfer_ct = transfer_ct_list;
    PrintSplitLine('-');
    std::cout << "successfully fill the struct of AnoyTransaction" << std::endl;
    std::string transcript_str = "";
    //begin to generate NIZK proof for validity of tx
    PrintSplitLine('-');
    std::cout << "begin to generate NIZK proof for validity of tx" << std::endl;
    
    ManyOutOfMany::PP many_out_of_many_pp;
    many_out_of_many_pp= ManyOutOfMany::Setup(AnoyTransaction.number,AnoyTransaction.Log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout<<"successfully setup the ManyOutOfMany Proof"<<std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;

    many_out_of_many_instance.vec_pk=AnoyTransaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        many_out_of_many_instance.vec_cipher_balance_left[i] = AnoyTransaction.balance_act[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = AnoyTransaction.balance_act[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = AnoyTransaction.transfer_ct[i].Y;
    }
    many_out_of_many_instance.cipher_transfer_right =AnoyTransaction.transfer_ct[0].X;
    
    many_out_of_many_instance.gepoch=AnoyTransaction.gepoch;
    many_out_of_many_instance.uepoch=AnoyTransaction.uepoch;


    /*Home add */
    for(size_t i=0;i<AnoyTransaction.number;i++){
       AnoyTransaction.balance_act[i]=ExponentialElGamal::HomoAdd(AnoyTransaction.balance_act[i],
                                                            AnoyTransaction.transfer_ct[i]); 
       many_out_of_many_instance.vec_cipher_balance_left[i] = AnoyTransaction.balance_act[i].Y;
       many_out_of_many_instance.vec_cipher_balance_right[i] = AnoyTransaction.balance_act[i].X;                                                    
    }
    PrintSplitLine('-');
    std::cout<<"successfully fill the instance of the proof"<<std::endl;
    ManyOutOfMany::Witness many_out_of_many_witness;

    many_out_of_many_witness.sender_index=sender_index;
    many_out_of_many_witness.receiver_index=receiver_index;
    many_out_of_many_witness.value=v;
    many_out_of_many_witness.r=r;
    many_out_of_many_witness.sk=Acct_sender.sk;
    PrintSplitLine('-');
    std::cout<<"begin to decrypt the balance of the sender"<<std::endl;
    many_out_of_many_witness.vprime=ExponentialElGamal::Dec(pp.enc_part,Acct_sender.sk,
                                    AnoyTransaction.balance_act[sender_index]);
    PrintSplitLine('-');
    std::cout<<"successfully decrypt the balance of the sender"<<std::endl;
    
    //vprime =sender's balance - transfer value
    size_t vprime_size_t=many_out_of_many_witness.vprime.ToUint64();
    PrintSplitLine('-');
    std::cout<<"vprime_size_t="<<vprime_size_t<<std::endl;

    ManyOutOfMany::ConsRandom cons_random;
    ManyOutOfMany::Proof proof_many_out_of_many_proof;

    PrintSplitLine('-');
    std::cout<<"begin to prove the validity of the transaction"<<std::endl;
    ManyOutOfMany::Prove(many_out_of_many_pp, many_out_of_many_witness,many_out_of_many_instance,
                 transcript_str,proof_many_out_of_many_proof,cons_random);

    AnoyTransaction.proof_many_out_of_many_proof = proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout<<"successfully generate the NIZK proof for validity of tx"<<std::endl;

    SigmaBullet::Instance sigmabullet_instance;
    SigmaBullet::Witness sigmabullet_witness;
    SigmaBullet::Proof proof_sigma_bullet_proof;
    sigmabullet_instance.cipher_transfer_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_right.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        sigmabullet_instance.cipher_transfer_left[i]=AnoyTransaction.transfer_ct[i].Y;
        sigmabullet_instance.cipher_transfer_right[i]=AnoyTransaction.transfer_ct[i].X;
    }
    for(size_t i=0;i<AnoyTransaction.number;i++){
        sigmabullet_instance.cipher_balance_left[i]=AnoyTransaction.balance_act[i].Y;
        sigmabullet_instance.cipher_balance_left[i]=AnoyTransaction.balance_act[i].X;
    }
    sigmabullet_witness.v={v,many_out_of_many_witness.vprime};
    transcript_str="";
    PrintSplitLine('-');
    std::cout<<"begin to prove the sigma bullet proof"<<std::endl;
    SigmaBullet::Prove(pp.sigmabullet_part,sigmabullet_instance,sigmabullet_witness,
                transcript_str,proof_sigma_bullet_proof,cons_random,proof_many_out_of_many_proof);
    PrintSplitLine('-');
    std::cout<<"successfully generate the sigma bullet proof"<<std::endl;
    AnoyTransaction.proof_sigma_bullet_proof = proof_sigma_bullet_proof;

    //the way 2
    MultiPlaintextEquality::PP multi_plaintext_equality_pp = MultiPlaintextEquality::Setup(pp.enc_part,AnoyTransaction.number,pp.pka);

    MultiPlaintextEquality::Instance multi_plaintext_equality_instance;
    multi_plaintext_equality_instance.vec_pk=pk_list;
    MultiPlaintextEquality::Witness multi_plaintext_equality_witness;
    multi_plaintext_equality_witness.r=r;
    AnoyTransaction.Supervise_ct.resize(AnoyTransaction.number);
    multi_plaintext_equality_instance.vec_cipher_transfer.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        multi_plaintext_equality_instance.vec_cipher_transfer[i]=AnoyTransaction.transfer_ct[i];
    }
    multi_plaintext_equality_instance.vec_cipher_supervision.resize(AnoyTransaction.number);
    
    multi_plaintext_equality_witness.vec_cipher_supervision_r.resize(AnoyTransaction.number);
    multi_plaintext_equality_witness.vec_cipher_v.resize(AnoyTransaction.number);

    BigInt Supervise2_vec_r;
    std::vector<ExponentialElGamal::CT>test(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        Supervise2_vec_r=GenRandomBigIntLessThan(order);
        multi_plaintext_equality_witness.vec_cipher_supervision_r[i]=Supervise2_vec_r;
        if(i==sender_index)
        {
            AnoyTransaction.Supervise_ct[i]=ExponentialElGamal::Enc(pp.enc_part,pp.pka,-v,Supervise2_vec_r);
            
            multi_plaintext_equality_witness.vec_cipher_v[i]=-v;
        }
        else if(i==receiver_index)
        {
            AnoyTransaction.Supervise_ct[i]=ExponentialElGamal::Enc(pp.enc_part,pp.pka,v,Supervise2_vec_r);
            
            multi_plaintext_equality_witness.vec_cipher_v[i]=v;
        }
        else
        {
            AnoyTransaction.Supervise_ct[i]=ExponentialElGamal::Enc(pp.enc_part,pp.pka,bn_0,Supervise2_vec_r);
            
            multi_plaintext_equality_witness.vec_cipher_v[i]=bn_0;
        }
        multi_plaintext_equality_instance.vec_cipher_supervision[i]=AnoyTransaction.Supervise_ct[i];  
            
    }
    
    std::string transcript_Supervise_str2 = "";
    //std::cout<<"begin to prove the Supervise knowledge2"<<std::endl;
    AnoyTransaction.proof_Supervise_knowledge2_proof = MultiPlaintextEquality::Prove(multi_plaintext_equality_pp, multi_plaintext_equality_instance, 
                                                    multi_plaintext_equality_witness, transcript_Supervise_str2);

    PrintSplitLine('-');
    std::cout<<"successfully generate the Supervise knowledge2 proof"<<std::endl;
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "AnoyTransaction generation2 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return AnoyTransaction;
}
bool VerifyAnoyTX1(PP &pp, StofAnoyTransaction1 AnoyTransaction)
{
    PrintSplitLine('-');
    std::cout << "begin to verify AnoyTransaction >>>>>>" << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 
    std::string transcript_str = "";
    //std::cout << "begin to setup the ManyOutOfMany Proof-verify " << std::endl;
    ManyOutOfMany::PP many_out_of_many_pp = ManyOutOfMany::Setup(AnoyTransaction.number,AnoyTransaction.Log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout<<"successfully setup the ManyOutOfMany Proof-verify"<<std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;

    many_out_of_many_instance.vec_pk=AnoyTransaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++)
    {
        many_out_of_many_instance.vec_cipher_balance_left[i] = AnoyTransaction.balance_act[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = AnoyTransaction.balance_act[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = AnoyTransaction.transfer_ct[i].Y;
    }
    many_out_of_many_instance.cipher_transfer_right =AnoyTransaction.transfer_ct[0].X;
    many_out_of_many_instance.gepoch=AnoyTransaction.gepoch;
    many_out_of_many_instance.uepoch=AnoyTransaction.uepoch;

    //ManyOutOfMany::Proof AnoyTransaction.proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout<<"begin to verify the ManyOutOfMany proof"<<std::endl;
    bool condition1 = ManyOutOfMany::Verify(many_out_of_many_pp, many_out_of_many_instance, 
                                   transcript_str, AnoyTransaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition1) std::cout << "ManyOutOfMany proof accepts" << std::endl; 
        else std::cout << "ManyOutOfMany proof rejects" << std::endl; 
    #endif

    //check sigma bullet proof
    transcript_str = "";
    SigmaBullet::Instance sigmabullet_instance;
    sigmabullet_instance.cipher_transfer_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_right.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        sigmabullet_instance.cipher_transfer_left[i]=AnoyTransaction.transfer_ct[i].Y;
        sigmabullet_instance.cipher_transfer_right[i]=AnoyTransaction.transfer_ct[i].X;
        sigmabullet_instance.cipher_balance_left[i]=AnoyTransaction.balance_act[i].Y;
        sigmabullet_instance.cipher_balance_right[i]=AnoyTransaction.balance_act[i].X;
    }
    //SigmaBullet::Proof proof_sigma_bullet_proof;
    bool condition2 = SigmaBullet::Verify(pp.sigmabullet_part,sigmabullet_instance,transcript_str,AnoyTransaction.proof_sigma_bullet_proof,AnoyTransaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition2) std::cout << "SigmaBullet proof accepts" << std::endl; 
        else std::cout << "SigmaBullet proof rejects" << std::endl;
    #endif
    //check Supervise way 1
    bool condition3;
    transcript_str = "";
    PlaintextBitEquality::PP plaintext_bit_equality_pp = PlaintextBitEquality::Setup(pp.enc_part,AnoyTransaction.number,pp.pka);
    PlaintextBitEquality::Instance plaintext_bit_equality_instance;
    plaintext_bit_equality_instance.vec_pk=AnoyTransaction.pk;
    plaintext_bit_equality_instance.value_cipher_supervison=AnoyTransaction.value_cipher_supervison;
    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_sender=AnoyTransaction.Supervise_indexl0;
    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_receiver=AnoyTransaction.Supervise_indexl1;
    plaintext_bit_equality_instance.vec_cipher_transfer=AnoyTransaction.transfer_ct;
    condition3 = PlaintextBitEquality::Verify(plaintext_bit_equality_pp, plaintext_bit_equality_instance, 
                                   transcript_str, AnoyTransaction.proof_Supervise_knowledge1_proof,AnoyTransaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition3) std::cout << "PlaintextBitEquality proof accepts" << std::endl; 
        else std::cout << "PlaintextBitEquality proof rejects" << std::endl;
    #endif
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "AnoyTransaction verification1 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    bool condition=condition1&&condition2&&condition3;
    return condition;
}

bool VerifyAnoyTX2(PP &pp, StofAnoyTransaction2 AnoyTransaction)
{
    PrintSplitLine('-');
    std::cout << "begin to verify AnoyTransaction >>>>>>" << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 
    std::string transcript_str = "";
    //std::cout << "begin to setup the ManyOutOfMany Proof-verify " << std::endl;
    ManyOutOfMany::PP many_out_of_many_pp = ManyOutOfMany::Setup(AnoyTransaction.number,AnoyTransaction.Log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout<<"successfully setup the ManyOutOfMany Proof-verify"<<std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;
    
    many_out_of_many_instance.vec_pk=AnoyTransaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(AnoyTransaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        many_out_of_many_instance.vec_cipher_balance_left[i] = AnoyTransaction.balance_act[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = AnoyTransaction.balance_act[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = AnoyTransaction.transfer_ct[i].Y;
    }
    many_out_of_many_instance.cipher_transfer_right =AnoyTransaction.transfer_ct[0].X;
    many_out_of_many_instance.gepoch=AnoyTransaction.gepoch;
    many_out_of_many_instance.uepoch=AnoyTransaction.uepoch;

    //ManyOutOfMany::Proof AnoyTransaction.proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout<<"begin to verify the ManyOutOfMany proof"<<std::endl;
    bool condition1 = ManyOutOfMany::Verify(many_out_of_many_pp, many_out_of_many_instance, 
                                   transcript_str, AnoyTransaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition1) std::cout << "ManyOutOfMany proof accepts" << std::endl; 
        else std::cout << "ManyOutOfMany proof rejects" << std::endl; 
    #endif

    
    //check sigma bullet proof
    transcript_str = "";
    SigmaBullet::Instance sigmabullet_instance;
    sigmabullet_instance.cipher_transfer_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_left.resize(AnoyTransaction.number);
    sigmabullet_instance.cipher_balance_right.resize(AnoyTransaction.number);
    for(size_t i=0;i<AnoyTransaction.number;i++){
        sigmabullet_instance.cipher_transfer_left[i]=AnoyTransaction.transfer_ct[i].Y;
        sigmabullet_instance.cipher_transfer_right[i]=AnoyTransaction.transfer_ct[i].X;
        sigmabullet_instance.cipher_balance_left[i]=AnoyTransaction.balance_act[i].Y;
        sigmabullet_instance.cipher_balance_right[i]=AnoyTransaction.balance_act[i].X;
    }
    //SigmaBullet::Proof proof_sigma_bullet_proof;
    bool condition2 = SigmaBullet::Verify(pp.sigmabullet_part,sigmabullet_instance,transcript_str,AnoyTransaction.proof_sigma_bullet_proof,AnoyTransaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition2) std::cout << "SigmaBullet proof accepts" << std::endl; 
        else std::cout << "SigmaBullet proof rejects" << std::endl;
    #endif
    
    bool condition3;
    transcript_str = "";
    MultiPlaintextEquality::PP multi_plaintext_equality_pp = MultiPlaintextEquality::Setup(pp.enc_part,AnoyTransaction.number,pp.pka);
    MultiPlaintextEquality::Instance multi_plaintext_equality_instance;
    multi_plaintext_equality_instance.vec_pk=AnoyTransaction.pk;
    multi_plaintext_equality_instance.vec_cipher_transfer=AnoyTransaction.transfer_ct;
    multi_plaintext_equality_instance.vec_cipher_supervision=AnoyTransaction.Supervise_ct;
    condition3 = MultiPlaintextEquality::Verify(multi_plaintext_equality_pp, multi_plaintext_equality_instance, 
                                   transcript_str, AnoyTransaction.proof_Supervise_knowledge2_proof);
    #ifdef DEMO
        if (condition3) std::cout << "MultiPlaintextEquality proof accepts" << std::endl; 
        else std::cout << "MultiPlaintextEquality proof rejects" << std::endl;
    #endif

    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "AnoyTransaction verification2 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    bool condition=condition1&&condition2&&condition3;
    return condition;
}


std::string ExtractToSignMessageFromAnoyTx(StofAnoyTransaction1 AnoyTransaction)
{
    std::string str;
    size_t number=AnoyTransaction.number;
    for(auto i=0;i<number;i++)
    {
        str+=AnoyTransaction.identity[i];
        str+=AnoyTransaction.pk[i].ToHexString();
        str+=AnoyTransaction.balance_act[i].X.ToHexString();
        str+=AnoyTransaction.balance_act[i].Y.ToHexString();
        str+=AnoyTransaction.transfer_ct[i].X.ToHexString();
        str+=AnoyTransaction.transfer_ct[i].Y.ToHexString();
    }
    str+=AnoyTransaction.epnumber.ToHexString();
    return str;
}

void UpdateAccount(PP &pp, StofAnoyTransaction1 &AnoyTransaction,std::vector<Account> AccountList_miner)
{     
    // update the balance
    std::cout << "update accounts >>>" << std::endl;
    for(auto i=0;i<AnoyTransaction.number;i++)
    {
        AccountList_miner[i].balance_ct=AnoyTransaction.balance_act[i];
        AccountList_miner[i].m=ExponentialElGamal::Dec(pp.enc_part,AccountList_miner[i].sk,AccountList_miner[i].balance_ct);
        SaveAccount(AccountList_miner[i], AccountList_miner[i].identity+".account");
    }
      
} 

void UpdateAccount(PP &pp, StofAnoyTransaction2 &AnoyTransaction,std::vector<Account> AccountList_miner)
{     
    // update the balance
    std::cout << "update accounts >>>" << std::endl;
    for(auto i=0;i<AnoyTransaction.number;i++)
    {
        AccountList_miner[i].balance_ct=AnoyTransaction.balance_act[i];
        AccountList_miner[i].m=ExponentialElGamal::Dec(pp.enc_part,AccountList_miner[i].sk,AccountList_miner[i].balance_ct);
        SaveAccount(AccountList_miner[i], AccountList_miner[i].identity+".account");
    }
      
} 
/* check if a anonymous tx is valid and update accounts if so */
//we use a dirty way to realize the function,miner should not have the account.sk
bool Miner1(PP &pp,StofAnoyTransaction1 AnoyTransaction,std::vector<Account> AccountList_miner)
{
    std::string tx_file = GetAnoyTxFileName(AnoyTransaction); 
    
    if(VerifyAnoyTX1(pp, AnoyTransaction) == true){
        UpdateAccount(pp, AnoyTransaction,AccountList_miner);
        SaveAnonyTx1(AnoyTransaction, tx_file);  //need to realize
        std::cout << tx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << tx_file << " is discarded" << std::endl; 
        return false; 
    }

}

bool Miner2(PP &pp,StofAnoyTransaction2 AnoyTransaction,std::vector<Account> AccountList_miner)
{
    std::string tx_file = GetAnoyTxFileName(AnoyTransaction); 
    
    if(VerifyAnoyTX2(pp, AnoyTransaction) == true){
        UpdateAccount(pp, AnoyTransaction,AccountList_miner);
        SaveAnonyTx2(AnoyTransaction, tx_file);  //need to realize
        std::cout << tx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << tx_file << " is discarded" << std::endl; 
        return false; 
    }

}

/* supervisor opens CTx */
SuperviseResult SuperviseAnoyTx1(SP &sp, PP &pp,  StofAnoyTransaction1 &AnoyTransaction)
{
    std::cout << "Supervise " << GetAnoyTxFileName(AnoyTransaction) << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    size_t number=AnoyTransaction.number;
    size_t Log_number=AnoyTransaction.Log_number;
    ExponentialElGamal::CT value_cipher_supervison=AnoyTransaction.value_cipher_supervison;
    std::vector<ExponentialElGamal::CT>Supervise_indexl0=AnoyTransaction.Supervise_indexl0;
    std::vector<ExponentialElGamal::CT>Supervise_indexl1=AnoyTransaction.Supervise_indexl1;
    BigInt v = ExponentialElGamal::Dec(pp.enc_part, sp.ska, value_cipher_supervison);
    SuperviseResult Supervise_result;
    Supervise_result.value_cipher_supervison=v;
    Supervise_result.Supervise_sender_index=0;
    Supervise_result.Supervise_receiver_index=0;
    for(auto i=0;i<Log_number;i++)
    {
        BigInt Supervise_indexl0_v=ExponentialElGamal::Dec(pp.enc_part, sp.ska, Supervise_indexl0[i]);
        BigInt Supervise_indexl1_v=ExponentialElGamal::Dec(pp.enc_part, sp.ska, Supervise_indexl1[i]);
        if(Supervise_indexl0_v!=bn_0)
        {
            Supervise_result.Supervise_sender_index+=pow(2,i);
        }
        if(Supervise_indexl1_v!=bn_0)
        {
            Supervise_result.Supervise_receiver_index+=pow(2,i);
        }
    }
    Supervise_result.sender_pk=AnoyTransaction.pk[Supervise_result.Supervise_sender_index];
    Supervise_result.receiver_pk=AnoyTransaction.pk[Supervise_result.Supervise_receiver_index];
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "Supervise tx takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-');
    std::cout << Supervise_result.sender_pk.ToHexString() << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << Supervise_result.receiver_pk.ToHexString() << std::endl; 
    PrintSplitLine('-');
    std::cout << AnoyTransaction.identity[Supervise_result.Supervise_sender_index] << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << AnoyTransaction.identity[Supervise_result.Supervise_receiver_index] << std::endl; 
    return Supervise_result;
}
SuperviseResult SuperviseAnoyTx2(SP &sp, PP &pp,  StofAnoyTransaction2 &AnoyTransaction)
{
    std::cout << "Supervise " << GetAnoyTxFileName(AnoyTransaction) << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    size_t number=AnoyTransaction.number;
    SuperviseResult Supervise_result;
    for(auto i=0;i<number;i++)
    {
        BigInt v = ExponentialElGamal::Dec(pp.enc_part, sp.ska, AnoyTransaction.Supervise_ct[i]);
        //if add the check the value of sender is consistent with the value of the receiver is also ok,but it is not necessary
        if(v<bn_0)
        {
            Supervise_result.Supervise_sender_index=i;
            Supervise_result.sender_pk=AnoyTransaction.pk[i];
        }
        else if(v!=bn_0)
        {
            Supervise_result.Supervise_receiver_index=i;
            Supervise_result.receiver_pk=AnoyTransaction.pk[i];
            Supervise_result.value_cipher_supervison=v;
        }
        
    }
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "Supervise tx takes time = "
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    PrintSplitLine('-');
    std::cout << Supervise_result.sender_pk.ToHexString() << " transfers " << BN_bn2dec(Supervise_result.value_cipher_supervison.bn_ptr)
    << " coins to " << Supervise_result.receiver_pk.ToHexString() << std::endl;
    PrintSplitLine('-');
    std::cout << AnoyTransaction.identity[Supervise_result.Supervise_sender_index] << " transfers " << BN_bn2dec(Supervise_result.value_cipher_supervison.bn_ptr)
    << " coins to " <<AnoyTransaction.identity[Supervise_result.Supervise_receiver_index]<< std::endl;
    return Supervise_result;

}

}
#endif
