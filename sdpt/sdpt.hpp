/****************************************************************************
this hpp implements the SDPT functionality 
*****************************************************************************/
#ifndef SDPT_HPP_
#define SDPT_HPP_

#include "../pke/exponential_elgamal.hpp"        // implement ElGamal  PKE
#include "../zkp/bulletproofs/sigma_bullet_proof.hpp"    // implement Log Size Bulletproof
#include "../zkp/nizk/nizk_many_out_of_many.hpp" // implement many out of many proof
#include "../zkp/nizk/nizk_plaintext_bit_equality.hpp" // NIZKPoK for plaintext bit equality
#include "../zkp/nizk/nizk_multi_plaintext_equality.hpp" // NIZKPoK for multi plaintext equality
#include "../utility/serialization.hpp"
#include <time.h>
#define DEMO           // demo mode 
//#define DEBUG        // show debug information 


namespace SDPT{

using Serialization::operator<<; 
using Serialization::operator>>; 


// define the structure of system parameters

struct PP
{    
    BigInt MAXIMUM_COINS; 
    size_t anonset_num; // the number of AnonSet,include the sender
    SigmaBullet::PP sigmabullet_part;
    ExponentialElGamal::PP enc_part;
    Pedersen::PP com_part;
    ECPoint pka; // supervisor's pk
};

// define the structure of system parameters
struct SP
{
    BigInt ska;   // supervisor's sk
};

struct Account
{
    std::string identity;     // id
    ECPoint pk;              // public key
    BigInt sk;              // secret key
    ExponentialElGamal::CT balance_ct;  // current balance
    BigInt m;               // dangerous (should only be used for speeding up the proof generation)
};

struct AnonSet
{
    std::string identity;
    ECPoint pk;
    ExponentialElGamal::CT balance_tx; // current balance
};

struct SupervisionResult
{
    BigInt cipher_supervison_value;
    size_t supervision_sender_index;
    size_t supervision_receiver_index;
    ECPoint sender_pk;
    ECPoint receiver_pk;
};

//the structure of Anonymous Transaction 1
struct AnonTransaction1
{
   BigInt epnumber; // the number of epoch
   ECPoint gepoch; // the generator of epoch
   ECPoint uepoch;// uepoch=gepoch^sender_sk
   size_t number; // the number of AnonSet + sender + receiver
   size_t log_number; // the log of number
   std::vector<std::string> identity; // the identity of participants;

   std::vector<ECPoint> pk; // the pk of participants;
   std::vector<ExponentialElGamal::CT> balance_tx; // the balance of participants;
   std::vector<ECPoint> transfer_tx_left; // the left part of transfer value of participants;
   ECPoint transfer_tx_right; // the right part of transfer value of participants; the randomness r is reuse,
                              // so the transfer_tx_right is the same for all participants, is equal to g^r
   //std::vector<ExponentialElGamal::CT> transfer_tx; // the transfer value of participants;

   //validity proof
   ManyOutOfMany::Proof proof_many_out_of_many_proof; // NIZKPoK for many out of many proof
    
   SigmaBullet::Proof proof_sigma_bullet_proof; // NIZKPoK for sigma bullet proof
   
   ExponentialElGamal::CT cipher_supervison_value;
   std::vector<ExponentialElGamal::CT> cipher_supervision_index_sender;
   std::vector<ExponentialElGamal::CT> cipher_supervision_index_receiver;
   //Superviseable proof
   PlaintextBitEquality::Proof proof_plaintext_bit_equality_proof; // NIZKPoK for the Plaintext Bit Equality

};

//the structure of Anonymous Transaction 2
struct AnonTransaction2
{
   BigInt epnumber; // the number of epoch
   ECPoint gepoch; // the generator of epoch
   ECPoint uepoch;// uepoch=gepoch^sender_sk
   size_t number; // the number of AnonSet + sender + receiver
   size_t log_number; // the index of sender
   std::vector<std::string> identity; // the identity of participants;

   std::vector<ECPoint> pk; // the pk of participants;
   std::vector<ExponentialElGamal::CT> balance_tx; // the balance of participants;
   std::vector<ECPoint> transfer_tx_left; // the left part of transfer value of participants;
   ECPoint transfer_tx_right; // the right part of transfer value of participants; the randomness r is reuse,
                              // so the transfer_tx_right is the same for all participants, is equal to g^r
   //std::vector<ExponentialElGamal::CT> transfer_tx; // the transfer value of participants;

   //validity proof
   ManyOutOfMany::Proof proof_many_out_of_many_proof; // NIZKPoK for many out of many proof
    
   SigmaBullet::Proof proof_sigma_bullet_proof; // NIZKPoK for sigma bullet proof
   std::vector<ExponentialElGamal::CT> cipher_supervison;
   //Superviseable proof
   MultiPlaintextEquality::Proof proof_multi_plaintext_equality_proof; // NIZKPoK for the Multi Plaintext Equality

};

std::string GetAnonTxFileName(AnonTransaction1 &anon_transaction)
{
    std::string tx_file = "Anonytx_way1_" + anon_transaction.epnumber.ToHexString() + ".tx";    
    return tx_file; 
}

std::string GetAnonTxFileName(AnonTransaction2 &anon_transaction)
{
    std::string tx_file = "Anonytx_way2_" + anon_transaction.epnumber.ToHexString() + ".tx";    
    return tx_file; 
}

void PrintPP(PP &pp)
{
    PrintSplitLine('-');
    std::cout << "pp content >>>>>>" << std::endl; 
    std::cout << "anonset_num = " << pp.anonset_num << std::endl; 
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

void PrintAnonyTX1(AnonTransaction1 &anon_transaction)
{
    PrintSplitLine('-');
    std::string tx_file = GetAnonTxFileName(anon_transaction);  
    std::cout << tx_file << " content >>>>>>" << std::endl; 

    std::cout << "epoch number >>>" << std::endl; 
    anon_transaction.epnumber.Print("epoch number"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    anon_transaction.gepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    anon_transaction.uepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "number of participants >>>" << anon_transaction.number << std::endl; 
    std::cout << "log_number of participants >>>" << anon_transaction.log_number << std::endl; 

    std::cout << "participants' identity >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        std::cout << anon_transaction.identity[i] << std::endl; 
    }
    std::cout << std::endl; 

    std::cout << "participants' pk >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        anon_transaction.pk[i].Print("pk"); 
    }
    std::cout << std::endl; 

    std::cout << "participants' balance >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        ExponentialElGamal::PrintCT(anon_transaction.balance_tx[i]); 
    }
    std::cout << std::endl; 

    std::cout << "participants' transfer >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        anon_transaction.transfer_tx_left[i].Print("transfer_tx_left");
        //ExponentialElGamal::PrintCT(anon_transaction.transfer_tx[i]); 
    }
    std::cout << std::endl; 
    anon_transaction.transfer_tx_right.Print("transfer_tx_right");

    std::cout << "NIZKPoK for many out of many  >>>" << std::endl; 
    ManyOutOfMany::PrintProof(anon_transaction.proof_many_out_of_many_proof);
    std::cout << std::endl;

    std::cout << "NIZKPoK for plaintext bit equality >>>" << std::endl;
    PlaintextBitEquality::PrintProof(anon_transaction.proof_plaintext_bit_equality_proof);
    std::cout << std::endl;

}

void PrintAnonyTX2(AnonTransaction2 &anon_transaction)
{
    PrintSplitLine('-');
    std::string tx_file = GetAnonTxFileName(anon_transaction);  
    std::cout << tx_file << " content >>>>>>" << std::endl; 

    std::cout << "epoch number >>>" << std::endl; 
    anon_transaction.epnumber.Print("epoch number"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    anon_transaction.gepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "epoch generator >>>" << std::endl; 
    anon_transaction.uepoch.Print("epoch generator"); 
    std::cout << std::endl; 

    std::cout << "number of participants >>>" << anon_transaction.number << std::endl; 
    std::cout << "log_number of participants >>>" << anon_transaction.log_number << std::endl; 

    std::cout << "participants' identity >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        std::cout << anon_transaction.identity[i] << std::endl; 
    }
    std::cout << std::endl; 

    std::cout << "participants' pk >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        anon_transaction.pk[i].Print("pk"); 
    }
    std::cout << std::endl; 

    std::cout << "participants' balance >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        ExponentialElGamal::PrintCT(anon_transaction.balance_tx[i]); 
    }
    std::cout << std::endl; 

    std::cout << "participants' transfer >>>" << std::endl; 
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        anon_transaction.transfer_tx_left[i].Print("transfer_tx_left");
        //ExponentialElGamal::PrintCT(anon_transaction.transfer_tx[i]); 
    }
    std::cout << std::endl; 
    anon_transaction.transfer_tx_right.Print("transfer_tx_right");

    std::cout << "NIZKPoK for many out of many  >>>" << std::endl; 
    ManyOutOfMany::PrintProof(anon_transaction.proof_many_out_of_many_proof);
    std::cout << std::endl;

    std::cout << "NIZKPoK for multi plaintext equality >>>" << std::endl;
    MultiPlaintextEquality::PrintProof(anon_transaction.proof_multi_plaintext_equality_proof);
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
    fout << pp.anonset_num;
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
    fin >> pp.anonset_num;
    fin >> pp.pka; 
 
    fin >> pp.sigmabullet_part;
    fin >> pp.enc_part; 
    fin >> pp.com_part;

    fin.close();   
}

void SaveAccount(Account &user, std::string sdp_account_file)
{
    std::ofstream fout; 
    fout.open(sdp_account_file, std::ios::binary);
    fout << user.identity;  
    fout << user.pk;              
    fout << user.sk;   
    fout << user.balance_ct;  
    fout << user.m; 
    fout.close();  
}

void FetchAccount(Account &user, std::string sdp_account_file)
{
    std::ifstream fin; 
    fin.open(sdp_account_file, std::ios::binary);
    fin >> user.identity; 
    fin >> user.pk;              
    fin >> user.sk;             
    fin >> user.balance_ct;
    fin >> user.m; 
    fin.close();  
}

void SaveAnonyTx1(AnonTransaction1 anon_transaction, std::string sdpt_anontx_file)
{
    std::ofstream fout; 
    fout.open(sdpt_anontx_file, std::ios::binary); 
    
    fout << anon_transaction.epnumber;
    fout << anon_transaction.gepoch;
    fout << anon_transaction.uepoch;
    size_t number = anon_transaction.number;
    for(auto i = 0; i < number; i++)
    {
        fout << anon_transaction.identity[i];
        fout << anon_transaction.pk[i];
        fout << anon_transaction.balance_tx[i];
        fout << anon_transaction.transfer_tx_left[i];
        //fout << anon_transaction.transfer_tx[i];
    }
    fout << anon_transaction.transfer_tx_right;
    // save proofs
    fout << anon_transaction.proof_many_out_of_many_proof;
    //save supertvisor's Supervise1 result and proof
    fout << anon_transaction.cipher_supervison_value;
    for(auto i = 0;i < anon_transaction.cipher_supervision_index_sender.size(); i++)
    {
        fout << anon_transaction.cipher_supervision_index_sender[i];
    }
    for(auto i = 0; i < anon_transaction.cipher_supervision_index_receiver.size(); i++)
    {
        fout << anon_transaction.cipher_supervision_index_receiver[i];
    }
    fout << anon_transaction.proof_plaintext_bit_equality_proof;
    
    fout.close();

    // calculate the size of tx_file
    std::ifstream fin; 
    fin.open(sdpt_anontx_file, std::ios::ate | std::ios::binary);
    std::cout << sdpt_anontx_file << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
    return;
}

void SaveAnonyTx2(AnonTransaction2 anon_transaction, std::string sdpt_anontx_file)
{
    std::ofstream fout; 
    fout.open(sdpt_anontx_file, std::ios::binary); 
    
    fout << anon_transaction.epnumber;
    fout << anon_transaction.gepoch;
    fout << anon_transaction.uepoch;
    size_t number=anon_transaction.number;
    for(auto i = 0; i < number; i++)
    {
        fout << anon_transaction.identity[i];
        fout << anon_transaction.pk[i];
        fout << anon_transaction.balance_tx[i];
        fout << anon_transaction.transfer_tx_left[i];
        //fout << anon_transaction.transfer_tx[i];
    }
    fout << anon_transaction.transfer_tx_right;
    // save proofs
    fout << anon_transaction.proof_many_out_of_many_proof;
    
    //save supertvisor's Supervise2 result and proof
    for(auto i = 0; i < anon_transaction.cipher_supervison.size(); i++)
    {
        fout << anon_transaction.cipher_supervison[i];
    }
    fout << anon_transaction.proof_multi_plaintext_equality_proof;
    fout.close();
    //to do list: the thrid way to Supervise the transaction

    // calculate the size of tx_file
    std::ifstream fin; 
    fin.open(sdpt_anontx_file, std::ios::ate | std::ios::binary);
    std::cout << sdpt_anontx_file << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
    return;
}

void FetchAnonyTx1(AnonTransaction1 &anon_transaction, std::string sdpt_anontx_file)
{
    // Deserialize_AnonyTx(anon_transaction, tx_file); 
    std::ifstream fin; 
    fin.open(sdpt_anontx_file);

    // recover 
    fin >> anon_transaction.epnumber;
    fin >> anon_transaction.gepoch;
    fin >> anon_transaction.uepoch;
    size_t number=anon_transaction.number;
    for(auto i = 0; i < number; i++)
    {
        fin >> anon_transaction.identity[i];
        fin >> anon_transaction.pk[i];
        fin >> anon_transaction.balance_tx[i];
        fin >> anon_transaction.transfer_tx_left[i];
        //fin >> anon_transaction.transfer_tx[i];
    }
    fin >> anon_transaction.transfer_tx_right;
    // recover proof
    fin >> anon_transaction.proof_many_out_of_many_proof;
    //recover supertvisor's Supervise1 result and proof
    fin >> anon_transaction.cipher_supervison_value;
    for(auto i = 0; i < anon_transaction.cipher_supervision_index_sender.size(); i++)
    {
        fin >> anon_transaction.cipher_supervision_index_sender[i];
    }
    for(auto i = 0; i < anon_transaction.cipher_supervision_index_receiver.size(); i++)
    {
        fin >> anon_transaction.cipher_supervision_index_receiver[i];
    }
    fin >> anon_transaction.proof_plaintext_bit_equality_proof;
   
    fin.close(); 
}

void FetchAnonyTx2(AnonTransaction2 &anon_transaction, std::string sdpt_anontx_file)
{
    // Deserialize_AnonyTx(anon_transaction, tx_file); 
    std::ifstream fin; 
    fin.open(sdpt_anontx_file);

    // recover 
    fin >> anon_transaction.epnumber;
    fin >> anon_transaction.gepoch;
    fin >> anon_transaction.uepoch;
    size_t number = anon_transaction.number;
    for(auto i = 0;i < number; i++)
    {
        fin >> anon_transaction.identity[i];
        fin >> anon_transaction.pk[i];
        fin >> anon_transaction.balance_tx[i];
        fin >> anon_transaction.transfer_tx_left[i];
        //fin >> anon_transaction.transfer_tx[i];
    }
    fin >> anon_transaction.transfer_tx_right;
    // recover proof
    fin >> anon_transaction.proof_many_out_of_many_proof;
    
    //recover supertvisor's Supervise2 result and proof
    for(auto i = 0; i < anon_transaction.cipher_supervison.size(); i++)
    {
        fin >> anon_transaction.cipher_supervison[i];
    }
    fin >> anon_transaction.proof_multi_plaintext_equality_proof;
    fin.close(); 
}

/* This function implements Setup algorithm of SDPT */
std::tuple<PP, SP> Setup(size_t LOG_MAXIMUM_COINS, size_t anonset_num)
{
    PP pp; 
    SP sp; 

    if(IsPowerOfTwo(anonset_num) == false)
    { 
        std::cout << "parameters warning: (anonset_num) had better be a power of 2" << std::endl;
    }  
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, LOG_MAXIMUM_COINS)));  
    pp.anonset_num = anonset_num;
    size_t MAX_AGG_NUM = anonset_num ;
    size_t Log_anonset_num = size_t(log2(anonset_num-1)+1);
    std::cout << "MAX_AGG_NUM = " << MAX_AGG_NUM << std::endl;
    std::cout << "Log_anonset_num = " << Log_anonset_num << std::endl;
    pp.sigmabullet_part = SigmaBullet::Setup(LOG_MAXIMUM_COINS, MAX_AGG_NUM); 
    
    size_t TRADEOFF_NUM = 7; 
    pp.enc_part = ExponentialElGamal::Setup(LOG_MAXIMUM_COINS, TRADEOFF_NUM);  
    pp.com_part = Pedersen::Setup(4*Log_anonset_num+2); // the size of the Pedersen commitment is 4*Log_anonset_num+2

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
    Account new_acct;
    new_acct.identity = identity;
    std::tie(new_acct.pk, new_acct.sk) = ExponentialElGamal::KeyGen(pp.enc_part); // generate a keypair
    new_acct.m = init_balance; 

    // initialize account balance with 0 coins
    BigInt r = Hash::StringToBigInt(new_acct.identity); 
    new_acct.balance_ct = ExponentialElGamal::Enc(pp.enc_part, new_acct.pk, init_balance, r);

    #ifdef DEMO
        std::cout << identity << "'s SDPT account creation succeeds" << std::endl;
        new_acct.pk.Print("pk"); 
        std::cout << identity << "'s initial balance = "; 
        new_acct.m.PrintInDec(); 
        std::cout << std::endl;
        PrintSplitLine('-'); 
    #endif 

    return new_acct;
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
AnonTransaction1 CreateAnonTransaction1(PP &pp, Account &Acct_sender, BigInt &v, std::vector<AnonSet> &AnonSetList, ECPoint &pkr, BigInt epnumber, size_t sender_index, size_t receiver_index)
{
    AnonTransaction1 anon_transaction;
    anon_transaction.number = AnonSetList.size();
    anon_transaction.log_number =size_t(log2(anon_transaction.number-1)+1); 
    PrintSplitLine('-');
    std::cout<<"the number of AnonSet is "<<anon_transaction.number<<std::endl;
    std::cout<<"the log_number of AnonSet is "<<anon_transaction.log_number<<std::endl;

    std::vector<std::string> identity_list(anon_transaction.number);
    std::vector<ECPoint> pk_list(anon_transaction.number);
    std::vector<ExponentialElGamal::CT> balance_tx_list(anon_transaction.number);
    std::vector<ExponentialElGamal::CT> transfer_tx_list(anon_transaction.number);

    auto start_time = std::chrono::steady_clock::now();
    /*fill the struct of vec */
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        identity_list[i] = AnonSetList[i].identity;
        pk_list[i] = AnonSetList[i].pk;
        balance_tx_list[i] = AnonSetList[i].balance_tx;
    }
    /*fill the struct of sender  */
    BigInt r = GenRandomBigIntLessThan(order); // the random r will be reused

    //we need to choose another way to generate the random r to prepare for the Supervise way 3 later
   
    transfer_tx_list[sender_index] = ExponentialElGamal::Enc(pp.enc_part, Acct_sender.pk, -v, r); // transfer -v coins to receiver

 
    transfer_tx_list[receiver_index] = ExponentialElGamal::Enc(pp.enc_part, pkr, v, r); // transfer v coins to receiver
 
    for(auto i = 0; i < anon_transaction.number; i++)
    {
        if(i != sender_index && i != receiver_index){
            transfer_tx_list[i] = ExponentialElGamal::Enc(pp.enc_part, AnonSetList[i].pk, bn_0, r); // transfer 0 coins to AnonSet
        }
    }
    
    anon_transaction.epnumber = epnumber;
    anon_transaction.gepoch = Hash::StringToECPoint("SDPT" + epnumber.ToHexString());
    anon_transaction.uepoch = anon_transaction.gepoch * Acct_sender.sk;
    anon_transaction.identity = identity_list;
    anon_transaction.pk = pk_list;
    anon_transaction.balance_tx = balance_tx_list;
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        anon_transaction.transfer_tx_left.push_back(transfer_tx_list[i].Y);
    }
    anon_transaction.transfer_tx_right = transfer_tx_list[0].X;
    //anon_transaction.transfer_tx = transfer_tx_list;
    PrintSplitLine('-');
    std::cout << "successfully fill the struct of anon_transaction" << std::endl;
    std::string transcript_str = "";
    //begin to generate NIZK proof for validity of tx
    PrintSplitLine('-');
    std::cout << "begin to generate NIZK proof for validity of tx" << std::endl;
    
    ManyOutOfMany::PP many_out_of_many_pp;
    many_out_of_many_pp = ManyOutOfMany::Setup(anon_transaction.number,anon_transaction.log_number, pp.com_part);
    PrintSplitLine('-');
    std::cout << "successfully setup the ManyOutOfMany Proof" << std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;

    many_out_of_many_instance.vec_pk = anon_transaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(anon_transaction.number);
    
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        many_out_of_many_instance.vec_cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = anon_transaction.balance_tx[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
    }
    many_out_of_many_instance.cipher_transfer_right = anon_transaction.transfer_tx_right;
    many_out_of_many_instance.gepoch = anon_transaction.gepoch;
    many_out_of_many_instance.uepoch = anon_transaction.uepoch;

    /*Home add */
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
       anon_transaction.balance_tx[i]=ExponentialElGamal::HomoAdd(anon_transaction.balance_tx[i], transfer_tx_list[i]); 
       many_out_of_many_instance.vec_cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
       many_out_of_many_instance.vec_cipher_balance_right[i] = anon_transaction.balance_tx[i].X;                                                    
    }
    PrintSplitLine('-');
    std::cout << "successfully fill the instance of the proof" << std::endl;
    ManyOutOfMany::Witness many_out_of_many_witness;

    many_out_of_many_witness.sender_index = sender_index;
    many_out_of_many_witness.receiver_index = receiver_index;
    many_out_of_many_witness.value = v;
    many_out_of_many_witness.r = r;
    many_out_of_many_witness.sk = Acct_sender.sk;
    PrintSplitLine('-');
    std::cout << "begin to decrypt the balance of the sender" << std::endl;
    many_out_of_many_witness.vprime = ExponentialElGamal::Dec(pp.enc_part, Acct_sender.sk, anon_transaction.balance_tx[sender_index]);
    PrintSplitLine('-');
    std::cout<<"successfully decrypt the balance of the sender"<<std::endl;
   
    // vprime = sender's balance-transfer value
    size_t vprime_size_t = many_out_of_many_witness.vprime.ToUint64();

    ManyOutOfMany::ConsistencyRandom consistency_random;
    ManyOutOfMany::Proof proof_many_out_of_many_proof;

    PrintSplitLine('-');
    std::cout<<"begin to prove the validity of the transaction"<<std::endl;
    ManyOutOfMany::Prove(many_out_of_many_pp, many_out_of_many_witness, many_out_of_many_instance,
                        transcript_str, proof_many_out_of_many_proof, consistency_random);

    anon_transaction.proof_many_out_of_many_proof = proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout << "successfully generate the NIZK proof for validity of tx" << std::endl;

    SigmaBullet::Instance sigmabullet_instance;
    SigmaBullet::Witness sigmabullet_witness;
    SigmaBullet::Proof proof_sigma_bullet_proof;
    sigmabullet_instance.cipher_transfer_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_right.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        sigmabullet_instance.cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
        sigmabullet_instance.cipher_transfer_right[i] = anon_transaction.transfer_tx_right;
    }
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        sigmabullet_instance.cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        sigmabullet_instance.cipher_balance_left[i] = anon_transaction.balance_tx[i].X;
    }
    sigmabullet_witness.v = {v, many_out_of_many_witness.vprime};
    transcript_str = "";
    PrintSplitLine('-');
    std::cout << "begin to prove the sigma bullet proof" << std::endl;
    SigmaBullet::Prove(pp.sigmabullet_part, sigmabullet_instance, sigmabullet_witness,
                    transcript_str, proof_sigma_bullet_proof, consistency_random, proof_many_out_of_many_proof);
    PrintSplitLine('-');
    std::cout << "successfully generate the sigma bullet proof" << std::endl;
    anon_transaction.proof_sigma_bullet_proof = proof_sigma_bullet_proof;

    //the way 1

    PlaintextBitEquality::PP plaintext_bit_equality_pp = PlaintextBitEquality::Setup(pp.enc_part,anon_transaction.number,pp.pka);
    PrintSplitLine('-');
    std::cout<<"successfully setup the PlaintextBitEquality Proof"<<std::endl;
    PlaintextBitEquality::Instance plaintext_bit_equality_instance;
    PlaintextBitEquality::Witness plaintext_bit_equality_witness;
    plaintext_bit_equality_witness.v = v;
    plaintext_bit_equality_instance.vec_cipher_transfer.resize(anon_transaction.number);
    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_v.resize(anon_transaction.log_number);
    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_v.resize(anon_transaction.log_number);
    plaintext_bit_equality_instance.vec_pk = anon_transaction.pk;
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        plaintext_bit_equality_instance.vec_cipher_transfer[i] = transfer_tx_list[i];
    }
    BigInt cipher_supervison_value_r = GenRandomBigIntLessThan(order);
    plaintext_bit_equality_witness.cipher_supervison_value_r = cipher_supervison_value_r;
    anon_transaction.cipher_supervison_value = ExponentialElGamal::Enc(pp.enc_part,pp.pka,v,cipher_supervison_value_r);
    plaintext_bit_equality_instance.cipher_supervison_value = anon_transaction.cipher_supervison_value;

    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_r.resize(anon_transaction.log_number);
    plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_r.resize(anon_transaction.log_number);
    anon_transaction.cipher_supervision_index_sender.resize(anon_transaction.log_number);
    anon_transaction.cipher_supervision_index_receiver.resize(anon_transaction.log_number);
    BigInt cipher_supervision_index_sender_r;
    BigInt cipher_supervision_index_receiver_r;
    BigInt cipher_supervision_index_sender_v;
    BigInt cipher_supervision_index_receiver_v;
    PrintSplitLine('-');
    std::cout << "begin to generate the vector index" << std::endl;

    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_sender.resize(anon_transaction.log_number);
    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_receiver.resize(anon_transaction.log_number);
    for(size_t i = 0; i < anon_transaction.log_number; i++)
    {
        cipher_supervision_index_sender_r = GenRandomBigIntLessThan(order);
        cipher_supervision_index_receiver_r = GenRandomBigIntLessThan(order);
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_r[i] = cipher_supervision_index_sender_r;
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_r[i] = cipher_supervision_index_receiver_r;

        if((sender_index >> i) & 1 == 1)
        {
            cipher_supervision_index_sender_v = bn_1;
        }
        else
        {
            cipher_supervision_index_sender_v = bn_0;
        }
        if((receiver_index >> i) & 1 == 1)
        {
            cipher_supervision_index_receiver_v = bn_1;
        }
        else
        {
            cipher_supervision_index_receiver_v = bn_0;
        }
        anon_transaction.cipher_supervision_index_sender[i] = ExponentialElGamal::Enc(pp.enc_part, pp.pka, cipher_supervision_index_sender_v, cipher_supervision_index_sender_r);
        anon_transaction.cipher_supervision_index_receiver[i] = ExponentialElGamal::Enc(pp.enc_part, pp.pka, cipher_supervision_index_receiver_v, cipher_supervision_index_receiver_r);
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_sender_v[i] = cipher_supervision_index_sender_v;
        plaintext_bit_equality_witness.vec_cipher_supervision_index_bit_receiver_v[i] = cipher_supervision_index_receiver_v;
        plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_sender[i] = anon_transaction.cipher_supervision_index_sender[i];
        plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_receiver[i] = anon_transaction.cipher_supervision_index_receiver[i];
    }
    std::string transcript_Supervise_str1 = "";
    PrintSplitLine('-');

    anon_transaction.proof_plaintext_bit_equality_proof = PlaintextBitEquality::Prove(plaintext_bit_equality_pp, plaintext_bit_equality_instance, 
                            plaintext_bit_equality_witness, anon_transaction.proof_many_out_of_many_proof, transcript_Supervise_str1, consistency_random);

    PrintSplitLine('-');
    std::cout << "successfully generate the Plaintext Bit Equality proof" << std::endl;
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "anon_transaction generation1 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    return anon_transaction;
}

// create a anonymous transaction2: pk1 transfers v coins to pk2
AnonTransaction2 CreateAnonTransaction2(PP &pp, Account &Acct_sender, BigInt &v, std::vector<AnonSet> &AnonSetList, ECPoint &pkr, BigInt epnumber, size_t sender_index, size_t receiver_index)
{
    
    AnonTransaction2 anon_transaction;
    anon_transaction.number = AnonSetList.size();
    anon_transaction.log_number = size_t(log2(anon_transaction.number-1)+1); 
    PrintSplitLine('-');
    std::cout << "the number of AnonSet is " << anon_transaction.number << std::endl;
    std::cout << "the log_number of AnonSet is " << anon_transaction.log_number << std::endl;

    std::vector<std::string> identity_list(anon_transaction.number);
    std::vector<ECPoint> pk_list(anon_transaction.number);
    std::vector<ExponentialElGamal::CT> balance_tx_list(anon_transaction.number);
    std::vector<ExponentialElGamal::CT> transfer_tx_list(anon_transaction.number);

    auto start_time = std::chrono::steady_clock::now();
    /*fill the struct of vec */
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        identity_list[i] = AnonSetList[i].identity;
        pk_list[i] = AnonSetList[i].pk;
        balance_tx_list[i] = AnonSetList[i].balance_tx;
    }
    /*fill the struct of sender  */
    BigInt r = GenRandomBigIntLessThan(order); // the random r will be reused
    
    transfer_tx_list[sender_index] = ExponentialElGamal::Enc(pp.enc_part, Acct_sender.pk, -v, r); // transfer -v coins to receiver

 
    transfer_tx_list[receiver_index] = ExponentialElGamal::Enc(pp.enc_part, pkr, v, r); // transfer v coins to receiver
 
    for(auto i = 0; i < anon_transaction.number; i++)
    {
        if(i != sender_index && i != receiver_index){
            transfer_tx_list[i] = ExponentialElGamal::Enc(pp.enc_part, AnonSetList[i].pk, bn_0, r); // transfer 0 coins to AnonSet
        }
    }
    
    anon_transaction.epnumber = epnumber;
    anon_transaction.gepoch = Hash::StringToECPoint("SDPT" + epnumber.ToHexString());
    anon_transaction.uepoch = anon_transaction.gepoch * Acct_sender.sk;
    anon_transaction.identity = identity_list;
    anon_transaction.pk = pk_list;
    anon_transaction.balance_tx = balance_tx_list;
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        anon_transaction.transfer_tx_left.push_back(transfer_tx_list[i].Y);
    }
    anon_transaction.transfer_tx_right = transfer_tx_list[0].X;
    //anon_transaction.transfer_tx = transfer_tx_list;
    PrintSplitLine('-');
    std::cout << "successfully fill the struct of anon_transaction" << std::endl;
    std::string transcript_str = "";
    //begin to generate NIZK proof for validity of tx
    PrintSplitLine('-');
    std::cout << "begin to generate NIZK proof for validity of tx" << std::endl;
    
    ManyOutOfMany::PP many_out_of_many_pp;
    many_out_of_many_pp = ManyOutOfMany::Setup(anon_transaction.number,anon_transaction.log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout << "successfully setup the ManyOutOfMany Proof" << std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;

    many_out_of_many_instance.vec_pk = anon_transaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        many_out_of_many_instance.vec_cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = anon_transaction.balance_tx[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
    }
    many_out_of_many_instance.cipher_transfer_right = anon_transaction.transfer_tx_right;
    many_out_of_many_instance.gepoch = anon_transaction.gepoch;
    many_out_of_many_instance.uepoch = anon_transaction.uepoch;

    /*Home add */
    for(size_t i = 0;i < anon_transaction.number; i++)
    {
       anon_transaction.balance_tx[i] = ExponentialElGamal::HomoAdd(anon_transaction.balance_tx[i], transfer_tx_list[i]); 
       many_out_of_many_instance.vec_cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
       many_out_of_many_instance.vec_cipher_balance_right[i] = anon_transaction.balance_tx[i].X;                                                    
    }
    PrintSplitLine('-');
    std::cout << "successfully fill the instance of the proof" << std::endl;
    ManyOutOfMany::Witness many_out_of_many_witness;

    many_out_of_many_witness.sender_index = sender_index;
    many_out_of_many_witness.receiver_index = receiver_index;
    many_out_of_many_witness.value = v;
    many_out_of_many_witness.r = r;
    many_out_of_many_witness.sk = Acct_sender.sk;
    PrintSplitLine('-');
    std::cout << "begin to decrypt the balance of the sender" << std::endl;
    many_out_of_many_witness.vprime = ExponentialElGamal::Dec(pp.enc_part,Acct_sender.sk,
                                    anon_transaction.balance_tx[sender_index]);
    PrintSplitLine('-');
    std::cout << "successfully decrypt the balance of the sender" << std::endl;
    
    //vprime =sender's balance - transfer value
    size_t vprime_size_t = many_out_of_many_witness.vprime.ToUint64();

    ManyOutOfMany::ConsistencyRandom consistency_random;
    ManyOutOfMany::Proof proof_many_out_of_many_proof;

    PrintSplitLine('-');
    std::cout << "begin to prove the validity of the transaction" << std::endl;
    ManyOutOfMany::Prove(many_out_of_many_pp, many_out_of_many_witness,many_out_of_many_instance,
                    transcript_str,proof_many_out_of_many_proof,consistency_random);

    anon_transaction.proof_many_out_of_many_proof = proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout<<"successfully generate the NIZK proof for validity of tx"<<std::endl;

    SigmaBullet::Instance sigmabullet_instance;
    SigmaBullet::Witness sigmabullet_witness;
    SigmaBullet::Proof proof_sigma_bullet_proof;
    sigmabullet_instance.cipher_transfer_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_right.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        sigmabullet_instance.cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
        sigmabullet_instance.cipher_transfer_right[i] = anon_transaction.transfer_tx_right;
    }
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        sigmabullet_instance.cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        sigmabullet_instance.cipher_balance_left[i] = anon_transaction.balance_tx[i].X;
    }
    sigmabullet_witness.v = {v,many_out_of_many_witness.vprime};
    transcript_str = "";
    PrintSplitLine('-');
    std::cout << "begin to prove the sigma bullet proof" << std::endl;
    SigmaBullet::Prove(pp.sigmabullet_part,sigmabullet_instance, sigmabullet_witness,
                    transcript_str, proof_sigma_bullet_proof, consistency_random, proof_many_out_of_many_proof);
    PrintSplitLine('-');
    std::cout << "successfully generate the sigma bullet proof" << std::endl;
    anon_transaction.proof_sigma_bullet_proof = proof_sigma_bullet_proof;

    //the way 2
    MultiPlaintextEquality::PP multi_plaintext_equality_pp = MultiPlaintextEquality::Setup(pp.enc_part,anon_transaction.number,pp.pka);

    MultiPlaintextEquality::Instance multi_plaintext_equality_instance;
    multi_plaintext_equality_instance.vec_pk = pk_list;
    MultiPlaintextEquality::Witness multi_plaintext_equality_witness;
    multi_plaintext_equality_witness.r = r;
    anon_transaction.cipher_supervison.resize(anon_transaction.number);
    multi_plaintext_equality_instance.vec_cipher_transfer.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        multi_plaintext_equality_instance.vec_cipher_transfer[i].Y = anon_transaction.transfer_tx_left[i];
        multi_plaintext_equality_instance.vec_cipher_transfer[i].X = anon_transaction.transfer_tx_right;
    }
    multi_plaintext_equality_instance.vec_cipher_supervision.resize(anon_transaction.number);
    multi_plaintext_equality_witness.vec_cipher_supervision_r.resize(anon_transaction.number);
    multi_plaintext_equality_witness.vec_cipher_v.resize(anon_transaction.number);

    BigInt cipher_supervison_r;
    for(size_t i = 0;i < anon_transaction.number; i++)
    {
        cipher_supervison_r=GenRandomBigIntLessThan(order);
        multi_plaintext_equality_witness.vec_cipher_supervision_r[i] = cipher_supervison_r;
        if(i == sender_index)
        {
            anon_transaction.cipher_supervison[i] = ExponentialElGamal::Enc(pp.enc_part,pp.pka,-v,cipher_supervison_r); 
            multi_plaintext_equality_witness.vec_cipher_v[i] = -v;
        }
        else if(i == receiver_index)
        {
            anon_transaction.cipher_supervison[i]=ExponentialElGamal::Enc(pp.enc_part,pp.pka,v,cipher_supervison_r);          
            multi_plaintext_equality_witness.vec_cipher_v[i] = v;
        }
        else
        {
            anon_transaction.cipher_supervison[i] = ExponentialElGamal::Enc(pp.enc_part,pp.pka,bn_0,cipher_supervison_r);
            multi_plaintext_equality_witness.vec_cipher_v[i] = bn_0;
        }
        multi_plaintext_equality_instance.vec_cipher_supervision[i] = anon_transaction.cipher_supervison[i];  
            
    }
    
    std::string transcript_supervision_str2 = "";
    anon_transaction.proof_multi_plaintext_equality_proof = MultiPlaintextEquality::Prove(multi_plaintext_equality_pp, multi_plaintext_equality_instance, 
                                                    multi_plaintext_equality_witness, transcript_supervision_str2);

    PrintSplitLine('-');
    std::cout<<"successfully generate the Multi Plaintext Equality proof"<<std::endl;
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "anon_transaction generation2 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return anon_transaction;
}
bool VerifyAnoyTX1(PP &pp, AnonTransaction1 anon_transaction)
{
    PrintSplitLine('-');
    std::cout << "begin to verify anon_transaction >>>>>>" << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 
    std::string transcript_str = "";
    //std::cout << "begin to setup the ManyOutOfMany Proof-verify " << std::endl;
    ManyOutOfMany::PP many_out_of_many_pp = ManyOutOfMany::Setup(anon_transaction.number,anon_transaction.log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout<<"successfully setup the ManyOutOfMany Proof-verify"<<std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;

    many_out_of_many_instance.vec_pk = anon_transaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(anon_transaction.number);
    for(size_t i = 0; i< anon_transaction.number; i++)
    {
        many_out_of_many_instance.vec_cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = anon_transaction.balance_tx[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
    }
    many_out_of_many_instance.cipher_transfer_right = anon_transaction.transfer_tx_right;
    many_out_of_many_instance.gepoch = anon_transaction.gepoch;
    many_out_of_many_instance.uepoch = anon_transaction.uepoch;

    //ManyOutOfMany::Proof anon_transaction.proof_many_out_of_many_proof;
    PrintSplitLine('-');
    std::cout << "begin to verify the ManyOutOfMany proof" << std::endl;
    bool condition1 = ManyOutOfMany::Verify(many_out_of_many_pp, many_out_of_many_instance, 
                                   transcript_str, anon_transaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition1) std::cout << "ManyOutOfMany proof accepts" << std::endl; 
        else std::cout << "ManyOutOfMany proof rejects" << std::endl; 
    #endif

    //check sigma bullet proof
    transcript_str = "";
    SigmaBullet::Instance sigmabullet_instance;
    sigmabullet_instance.cipher_transfer_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_right.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        sigmabullet_instance.cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
        sigmabullet_instance.cipher_transfer_right[i] = anon_transaction.transfer_tx_right;
        sigmabullet_instance.cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        sigmabullet_instance.cipher_balance_right[i] = anon_transaction.balance_tx[i].X;
    }
    //SigmaBullet::Proof proof_sigma_bullet_proof;
    bool condition2 = SigmaBullet::Verify(pp.sigmabullet_part, sigmabullet_instance, transcript_str, anon_transaction.proof_sigma_bullet_proof,
                                        anon_transaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition2) std::cout << "SigmaBullet proof accepts" << std::endl; 
        else std::cout << "SigmaBullet proof rejects" << std::endl;
    #endif
    //check Supervise way 1
    bool condition3;
    transcript_str = "";
    PlaintextBitEquality::PP plaintext_bit_equality_pp = PlaintextBitEquality::Setup(pp.enc_part,anon_transaction.number,pp.pka);
    PlaintextBitEquality::Instance plaintext_bit_equality_instance;
    plaintext_bit_equality_instance.vec_pk = anon_transaction.pk;
    plaintext_bit_equality_instance.cipher_supervison_value = anon_transaction.cipher_supervison_value;
    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_sender = anon_transaction.cipher_supervision_index_sender;
    plaintext_bit_equality_instance.vec_cipher_supervision_index_bit_receiver = anon_transaction.cipher_supervision_index_receiver;
    
    plaintext_bit_equality_instance.vec_cipher_transfer.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        plaintext_bit_equality_instance.vec_cipher_transfer[i].Y = anon_transaction.transfer_tx_left[i];
        plaintext_bit_equality_instance.vec_cipher_transfer[i].X = anon_transaction.transfer_tx_right;
    }
    //plaintext_bit_equality_instance.vec_cipher_transfer = anon_transaction.transfer_tx;

    condition3 = PlaintextBitEquality::Verify(plaintext_bit_equality_pp, plaintext_bit_equality_instance, 
                                   transcript_str, anon_transaction.proof_plaintext_bit_equality_proof, anon_transaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition3) std::cout << "PlaintextBitEquality proof accepts" << std::endl; 
        else std::cout << "PlaintextBitEquality proof rejects" << std::endl;
    #endif
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "anon_transaction verification1 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    bool condition = condition1 && condition2 && condition3;
    return condition;
}

bool VerifyAnoyTX2(PP &pp, AnonTransaction2 anon_transaction)
{
    PrintSplitLine('-');
    std::cout << "begin to verify anon_transaction >>>>>>" << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 
    std::string transcript_str = "";
    //std::cout << "begin to setup the ManyOutOfMany Proof-verify " << std::endl;
    ManyOutOfMany::PP many_out_of_many_pp = ManyOutOfMany::Setup(anon_transaction.number,anon_transaction.log_number,pp.com_part);
    PrintSplitLine('-');
    std::cout << "successfully setup the ManyOutOfMany Proof-verify" << std::endl;
    ManyOutOfMany::Instance many_out_of_many_instance;
    
    many_out_of_many_instance.vec_pk = anon_transaction.pk;
    many_out_of_many_instance.vec_cipher_balance_left.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_balance_right.resize(anon_transaction.number);
    many_out_of_many_instance.vec_cipher_transfer_left.resize(anon_transaction.number);
    for(size_t i = 0;i < anon_transaction.number; i++)
    {
        many_out_of_many_instance.vec_cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        many_out_of_many_instance.vec_cipher_balance_right[i] = anon_transaction.balance_tx[i].X;
        many_out_of_many_instance.vec_cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
    }
    many_out_of_many_instance.cipher_transfer_right = anon_transaction.transfer_tx_right;
    many_out_of_many_instance.gepoch = anon_transaction.gepoch;
    many_out_of_many_instance.uepoch = anon_transaction.uepoch;

    PrintSplitLine('-');
    std::cout << "begin to verify the ManyOutOfMany proof" << std::endl;
    bool condition1 = ManyOutOfMany::Verify(many_out_of_many_pp, many_out_of_many_instance, 
                                   transcript_str, anon_transaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition1) std::cout << "ManyOutOfMany proof accepts" << std::endl; 
        else std::cout << "ManyOutOfMany proof rejects" << std::endl; 
    #endif

    
    //check sigma bullet proof
    transcript_str = "";
    SigmaBullet::Instance sigmabullet_instance;
    sigmabullet_instance.cipher_transfer_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_transfer_right.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_left.resize(anon_transaction.number);
    sigmabullet_instance.cipher_balance_right.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        sigmabullet_instance.cipher_transfer_left[i] = anon_transaction.transfer_tx_left[i];
        sigmabullet_instance.cipher_transfer_right[i] = anon_transaction.transfer_tx_right;
        sigmabullet_instance.cipher_balance_left[i] = anon_transaction.balance_tx[i].Y;
        sigmabullet_instance.cipher_balance_right[i] = anon_transaction.balance_tx[i].X;
    }
    //SigmaBullet::Proof proof_sigma_bullet_proof;
    bool condition2 = SigmaBullet::Verify(pp.sigmabullet_part, sigmabullet_instance, transcript_str, anon_transaction.proof_sigma_bullet_proof,
                                        anon_transaction.proof_many_out_of_many_proof);
    #ifdef DEMO
        if (condition2) std::cout << "SigmaBullet proof accepts" << std::endl; 
        else std::cout << "SigmaBullet proof rejects" << std::endl;
    #endif
    
    bool condition3;
    transcript_str = "";
    MultiPlaintextEquality::PP multi_plaintext_equality_pp = MultiPlaintextEquality::Setup(pp.enc_part,anon_transaction.number,pp.pka);
    MultiPlaintextEquality::Instance multi_plaintext_equality_instance;
    multi_plaintext_equality_instance.vec_pk = anon_transaction.pk;
    multi_plaintext_equality_instance.vec_cipher_transfer.resize(anon_transaction.number);
    for(size_t i = 0; i < anon_transaction.number; i++)
    {
        multi_plaintext_equality_instance.vec_cipher_transfer[i].Y = anon_transaction.transfer_tx_left[i];
        multi_plaintext_equality_instance.vec_cipher_transfer[i].X = anon_transaction.transfer_tx_right;
    }
    //multi_plaintext_equality_instance.vec_cipher_transfer = anon_transaction.transfer_tx;
    multi_plaintext_equality_instance.vec_cipher_supervision = anon_transaction.cipher_supervison;
    condition3 = MultiPlaintextEquality::Verify(multi_plaintext_equality_pp, multi_plaintext_equality_instance, 
                                   transcript_str, anon_transaction.proof_multi_plaintext_equality_proof);
    #ifdef DEMO
        if (condition3) std::cout << "MultiPlaintextEquality proof accepts" << std::endl; 
        else std::cout << "MultiPlaintextEquality proof rejects" << std::endl;
    #endif

    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "anon_transaction verification2 takes time = "
                << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    bool condition = condition1 && condition2 && condition3;
    return condition;
}


std::string ExtractToSignMessageFromAnoyTx(AnonTransaction1 anon_transaction)
{
    std::string str;
    size_t number = anon_transaction.number;
    for(auto i = 0; i < number; i++)
    {
        str += anon_transaction.identity[i];
        str += anon_transaction.pk[i].ToHexString();
        str += anon_transaction.balance_tx[i].X.ToHexString();
        str += anon_transaction.balance_tx[i].Y.ToHexString();
        str += anon_transaction.transfer_tx_left[i].ToHexString();
        str += anon_transaction.transfer_tx_right.ToHexString();
        //str += anon_transaction.transfer_tx[i].X.ToHexString();
        //str += anon_transaction.transfer_tx[i].Y.ToHexString();
    }
    str += anon_transaction.epnumber.ToHexString();
    return str;
}

void UpdateAccount(PP &pp, AnonTransaction1 &anon_transaction, std::vector<Account> accountlist_miner)
{     
    // update the balance
    std::cout << "update accounts >>>" << std::endl;
    for(auto i = 0; i < anon_transaction.number; i++)
    {
        accountlist_miner[i].balance_ct = anon_transaction.balance_tx[i];
        accountlist_miner[i].m = ExponentialElGamal::Dec(pp.enc_part, accountlist_miner[i].sk, accountlist_miner[i].balance_ct);
        SaveAccount(accountlist_miner[i], accountlist_miner[i].identity + ".account");
    }
      
} 

void UpdateAccount(PP &pp, AnonTransaction2 &anon_transaction, std::vector<Account> accountlist_miner)
{     
    // update the balance
    std::cout << "update accounts >>>" << std::endl;
    for(auto i = 0; i < anon_transaction.number; i++)
    {
        accountlist_miner[i].balance_ct = anon_transaction.balance_tx[i];
        accountlist_miner[i].m = ExponentialElGamal::Dec(pp.enc_part,accountlist_miner[i].sk, accountlist_miner[i].balance_ct);
        SaveAccount(accountlist_miner[i], accountlist_miner[i].identity + ".account");
    }
      
} 
/* check if a anonymous tx is valid and update accounts if yes */
//we use a dirty way to realize the function,miner should not have the account.sk
bool Miner1(PP &pp,AnonTransaction1 anon_transaction,std::vector<Account> accountlist_miner)
{
    std::string tx_file = GetAnonTxFileName(anon_transaction); 
    
    if(VerifyAnoyTX1(pp, anon_transaction) == true){
        UpdateAccount(pp, anon_transaction, accountlist_miner);
        SaveAnonyTx1(anon_transaction, tx_file);  //need to realize
        std::cout << tx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << tx_file << " is discarded" << std::endl; 
        return false; 
    }

}

bool Miner2(PP &pp,AnonTransaction2 anon_transaction, std::vector<Account> accountlist_miner)
{
    std::string tx_file = GetAnonTxFileName(anon_transaction); 
    
    if(VerifyAnoyTX2(pp, anon_transaction) == true){
        UpdateAccount(pp, anon_transaction, accountlist_miner);
        SaveAnonyTx2(anon_transaction, tx_file);  //need to realize
        std::cout << tx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << tx_file << " is discarded" << std::endl; 
        return false; 
    }

}

/* supervisor opens CTx */
SupervisionResult SuperviseAnonTx1(SP &sp, PP &pp, AnonTransaction1 &anon_transaction)
{
    std::cout << "Supervise " << GetAnonTxFileName(anon_transaction) << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    size_t number = anon_transaction.number;
    size_t log_number = anon_transaction.log_number;
    ExponentialElGamal::CT cipher_supervison_value = anon_transaction.cipher_supervison_value;
    std::vector<ExponentialElGamal::CT>cipher_supervision_index_sender = anon_transaction.cipher_supervision_index_sender;
    std::vector<ExponentialElGamal::CT>cipher_supervision_index_receiver = anon_transaction.cipher_supervision_index_receiver;
    BigInt v = ExponentialElGamal::Dec(pp.enc_part, sp.ska, cipher_supervison_value);
    SupervisionResult supervision_result;
    supervision_result.cipher_supervison_value = v;
    supervision_result.supervision_sender_index = 0;
    supervision_result.supervision_receiver_index = 0;
    for(auto i = 0; i < log_number; i++)
    {
        BigInt cipher_supervision_index_sender_v = ExponentialElGamal::Dec(pp.enc_part, sp.ska, cipher_supervision_index_sender[i]);
        BigInt cipher_supervision_index_receiver_v = ExponentialElGamal::Dec(pp.enc_part, sp.ska, cipher_supervision_index_receiver[i]);
        if(cipher_supervision_index_sender_v != bn_0)
        {
            supervision_result.supervision_sender_index += pow(2,i);
        }
        if(cipher_supervision_index_receiver_v != bn_0)
        {
            supervision_result.supervision_receiver_index += pow(2,i);
        }
    }
    supervision_result.sender_pk = anon_transaction.pk[supervision_result.supervision_sender_index];
    supervision_result.receiver_pk = anon_transaction.pk[supervision_result.supervision_receiver_index];
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "Supervise tx takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintSplitLine('-');
    std::cout << supervision_result.sender_pk.ToHexString() << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << supervision_result.receiver_pk.ToHexString() << std::endl; 
    PrintSplitLine('-');
    std::cout << anon_transaction.identity[supervision_result.supervision_sender_index] << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << anon_transaction.identity[supervision_result.supervision_receiver_index] << std::endl; 
    return supervision_result;
}
SupervisionResult SuperviseAnonTx2(SP &sp, PP &pp,  AnonTransaction2 &anon_transaction)
{
    std::cout << "Supervise " << GetAnonTxFileName(anon_transaction) << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    size_t number = anon_transaction.number;
    SupervisionResult supervision_result;
    for(auto i = 0; i < number; i++)
    {
        BigInt v = ExponentialElGamal::Dec(pp.enc_part, sp.ska, anon_transaction.cipher_supervison[i]);
        //if add the check the value of sender is consistent with the value of the receiver is also ok,but it is not necessary
        if(v < bn_0)
        {
            supervision_result.supervision_sender_index = i;
            supervision_result.sender_pk = anon_transaction.pk[i];
        }
        else if(v != bn_0)
        {
            supervision_result.supervision_receiver_index = i;
            supervision_result.receiver_pk = anon_transaction.pk[i];
            supervision_result.cipher_supervison_value = v;
        }
        
    }
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;
    std::cout << "Supervise tx takes time = "
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    PrintSplitLine('-');
    std::cout << supervision_result.sender_pk.ToHexString() << " transfers " << BN_bn2dec(supervision_result.cipher_supervison_value.bn_ptr)
    << " coins to " << supervision_result.receiver_pk.ToHexString() << std::endl;
    PrintSplitLine('-');
    std::cout << anon_transaction.identity[supervision_result.supervision_sender_index] << " transfers " << BN_bn2dec(supervision_result.cipher_supervison_value.bn_ptr)
    << " coins to " <<anon_transaction.identity[supervision_result.supervision_receiver_index]<< std::endl;
    return supervision_result;

}

}
#endif
