/****************************************************************************
this hpp implements the ADCP functionality 
*****************************************************************************/
#ifndef ADCP_HPP_
#define ADCP_HPP_

#include "../pke/twisted_exponential_elgamal.hpp"        // implement Twisted ElGamal  
#include "../zkp/nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../zkp/nizk/nizk_plaintext_knowledge.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../zkp/nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../zkp/nizk/nizk_dlog_knowledge.hpp"     // NIZKPoK for dlog knowledge
#include "../zkp/bulletproofs/bullet_proof.hpp"    // implement Log Size Bulletproof
#include "../gadget/range_proof.hpp"
#include "../utility/serialization.hpp"

#define DEMO           // demo mode 
//#define DEBUG        // show debug information 

namespace ADCP{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define the structure of system parameters

struct PP{    
    size_t SN_LEN;    // sn length
    size_t MAX_RECEIVER_NUM; // number of maximum receivers (for now, we require this value to be 2^n - 1)
    BigInt MAXIMUM_COINS; 

    Bullet::PP bullet_part; 
    TwistedExponentialElGamal::PP enc_part;

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
    TwistedExponentialElGamal::CT balance_ct;  // current balance
    BigInt m;               // dangerous (should only be used for speeding up the proof generation)
    BigInt sn; 
};

// define the structure for confidential transaction
struct ToOneCTx{
    BigInt sn;                        // serial number: uniquely defines a transaction
    // memo information
    TwistedExponentialElGamal::CT sender_balance_ct;        // the current balance of pk1 (not necessarily included)
    ECPoint pks, pkr;      // sender = pk1, receiver = pk2
    TwistedExponentialElGamal::MRCT transfer_ct;    // transfer = (X0 = pks^r, X1 = pkr^r, X2 = pka^r Y = g^r h^v) 

    // validity proof
    PlaintextEquality::Proof plaintext_equality_proof;     // NIZKPoK for transfer ciphertext (X1, X2, Y)
    Bullet::Proof bullet_right_solvent_proof;      // aggregated range proof for v and m-v lie in the right range 
    TwistedExponentialElGamal::CT refresh_sender_updated_balance_ct;  // fresh encryption of updated balance (randomness is known)
    PlaintextKnowledge::Proof plaintext_knowledge_proof; // NIZKPoK for refresh ciphertext (X^*, Y^*)
    DLOGEquality::Proof correct_refresh_proof;     // fresh updated balance is correct
};

template <typename T>
std::string GetCTxFileName(T &newCTx)
{
    std::string ctx_file = newCTx.pks.ToHexString() + "_" + newCTx.sn.ToHexString()+".ctx"; 
    return ctx_file; 
}

void PrintPP(PP &pp)
{
    PrintSplitLine('-');
    std::cout << "pp content >>>>>>" << std::endl; 
    std::cout << "MAX_RECEIVER_NUM = " << pp.MAX_RECEIVER_NUM << std::endl; // number of sub-argument (for now, we require m to be the power of 2)
    std::cout << "SN_LEN = " << pp.SN_LEN << std::endl; 

    pp.pka.Print("supervisor's pk"); 
    
    PrintSplitLine('-'); 
}

void PrintAccount(Account &Acct)
{
    std::cout << Acct.identity << " account information >>> " << std::endl;     
    Acct.pk.Print("pk"); 
    std::cout << "encrypted balance:" << std::endl; 
    TwistedExponentialElGamal::PrintCT(Acct.balance_ct);  // current balance
    Acct.m.PrintInDec("m"); 
    Acct.sn.Print("sn"); 
    PrintSplitLine('-'); 
}

/* print the details of a confidential to-one-transaction */
void PrintCTx(ToOneCTx &newCTx)
{
    PrintSplitLine('-');
    std::string ctx_file = GetCTxFileName(newCTx);  
    std::cout << ctx_file << " content >>>>>>" << std::endl; 

    std::cout << "current sender balance >>>" << std::endl; 
    TwistedExponentialElGamal::PrintCT(newCTx.sender_balance_ct);
    std::cout << std::endl; 

    newCTx.pks.Print("sender's public key"); 
    newCTx.pkr.Print("receiver's public key"); 
    std::cout << std::endl;  

    std::cout << "transfer >>>" << std::endl;
    TwistedExponentialElGamal::PrintCT(newCTx.transfer_ct);
    std::cout << std::endl; 

    std::cout << "NIZKPoK for plaintext equality >>>" << std::endl; 
    PlaintextEquality::PrintProof(newCTx.plaintext_equality_proof);
    std::cout << std::endl; 

    std::cout << "refresh updated balance >>>" << std::endl;
    TwistedExponentialElGamal::PrintCT(newCTx.refresh_sender_updated_balance_ct); 
    std::cout << std::endl;

    std::cout << "NIZKPoK for refreshing correctness >>>" << std::endl; 
    DLOGEquality::PrintProof(newCTx.correct_refresh_proof);
    std::cout << std::endl;

    std::cout << "NIZKPoK of refresh updated balance >>>" << std::endl; 
    PlaintextKnowledge::PrintProof(newCTx.plaintext_knowledge_proof); 
    std::cout << std::endl;

    std::cout << "range proofs for transfer amount and updated balance >>> " << std::endl; 
    Bullet::PrintProof(newCTx.bullet_right_solvent_proof); 
    std::cout << std::endl;

    PrintSplitLine('-'); 
}


void SaveSP(SP &sp, std::string ADCP_SP_File)
{
    std::ofstream fout;
    fout.open(ADCP_SP_File, std::ios::binary); 
    fout << sp.ska;
    fout.close();   
}

void FetchSP(SP &sp, std::string ADCP_SP_File)
{
    std::ifstream fin; 
    fin.open(ADCP_SP_File, std::ios::binary); 
    fin >> sp.ska; 
    fin.close();   
}

void SavePP(PP &pp, std::string ADCP_PP_File)
{
    std::ofstream fout; 
    fout.open(ADCP_PP_File, std::ios::binary); 

    fout << pp.MAX_RECEIVER_NUM; 
    fout << pp.SN_LEN;
    fout << pp.MAXIMUM_COINS;  
    fout << pp.pka; 

    fout << pp.bullet_part; 
    fout << pp.enc_part; 

    fout.close();   
}

void FetchPP(PP &pp, std::string ADCP_PP_File)
{
    std::ifstream fin; 
    fin.open(ADCP_PP_File, std::ios::binary); 

    fin >> pp.MAX_RECEIVER_NUM;
    fin >> pp.SN_LEN; 
    fin >> pp.MAXIMUM_COINS;  
    fin >> pp.pka; 
 
    fin >> pp.bullet_part;
    fin >> pp.enc_part; 

    fin.close();   
}

void SaveAccount(Account &user, std::string ADCP_Account_File)
{
    std::ofstream fout; 
    fout.open(ADCP_Account_File, std::ios::binary);
    fout << user.identity;  
    fout << user.pk;              
    fout << user.sk;   
    fout << user.balance_ct;  
    fout << user.m; 
    fout << user.sn;
    fout.close();  
}

void FetchAccount(Account &user, std::string adcp_Account_File)
{
    std::ifstream fin; 
    fin.open(adcp_Account_File, std::ios::binary);
    fin >> user.identity; 
    fin >> user.pk;              
    fin >> user.sk;             
    fin >> user.balance_ct;
    fin >> user.m; 
    fin >> user.sn;
    fin.close();  
}

// save CTx into sn.ctx file
void SaveCTx(ToOneCTx &newCTx, std::string ADCP_CTx_File)
{
    std::ofstream fout; 
    fout.open(ADCP_CTx_File, std::ios::binary); 
    
    // save sn
    fout << newCTx.sn; 
     
    // save memo info
    fout << newCTx.pks; 
    fout << newCTx.pkr; 
    fout << newCTx.transfer_ct; 
    
    // save proofs
    fout << newCTx.plaintext_equality_proof;
    fout << newCTx.refresh_sender_updated_balance_ct; 
    fout << newCTx.correct_refresh_proof; 
    fout << newCTx.plaintext_knowledge_proof; 
    fout << newCTx.bullet_right_solvent_proof;
    fout.close();

    // calculate the size of ctx_file
    std::ifstream fin; 
    fin.open(ADCP_CTx_File, std::ios::ate | std::ios::binary);
    std::cout << ADCP_CTx_File << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
}

/* recover CTx from ctx file */
void FetchCTx(ToOneCTx &newCTx, std::string ADCP_CTx_File)
{
    // Deserialize_CTx(newCTx, ctx_file); 
    std::ifstream fin; 
    fin.open(ADCP_CTx_File);

    // recover sn
    fin >> newCTx.sn;
    
    // recover memo
    fin >> newCTx.pks; 
    fin >> newCTx.pkr; 
    fin >> newCTx.transfer_ct;

    // recover proof
    fin >> newCTx.plaintext_equality_proof;
    fin >> newCTx.refresh_sender_updated_balance_ct; 
    fin >> newCTx.correct_refresh_proof; 
    fin >> newCTx.plaintext_knowledge_proof; 
    fin >> newCTx.bullet_right_solvent_proof; 
    fin.close(); 
}

/* This function implements Setup algorithm of ADCP */
std::tuple<PP, SP> Setup(size_t LOG_MAXIMUM_COINS, size_t MAX_RECEIVER_NUM, size_t SN_LEN)
{
    PP pp; 
    SP sp; 

    pp.MAX_RECEIVER_NUM = MAX_RECEIVER_NUM; 
    if(IsPowerOfTwo(MAX_RECEIVER_NUM+1) == false){
        std::cerr << "parameters wrong: (MAX_RECEIVER_NUM+1) must be a power of 2" << std::endl; 
    }
    pp.SN_LEN = SN_LEN;    
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, LOG_MAXIMUM_COINS)));  


    size_t MAX_AGG_NUM = pp.MAX_RECEIVER_NUM + 1; 

    pp.bullet_part = Bullet::Setup(LOG_MAXIMUM_COINS, MAX_AGG_NUM); 
    
    size_t TRADEOFF_NUM = 7;
    pp.enc_part = TwistedExponentialElGamal::Setup(LOG_MAXIMUM_COINS, TRADEOFF_NUM);  

    std::tie(pp.pka, sp.ska) = TwistedExponentialElGamal::KeyGen(pp.enc_part);

    return {pp, sp};
}

/* initialize the encryption part for faster decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize ADCP >>>" << std::endl;  
    TwistedExponentialElGamal::Initialize(pp.enc_part); 
    PrintSplitLine('-'); 
}

/* create an account for input identity */
Account CreateAccount(PP &pp, std::string identity, BigInt &init_balance, BigInt &init_sn)
{
    Account newAcct;
    newAcct.identity = identity;
    newAcct.sn = init_sn;  

    std::tie(newAcct.pk, newAcct.sk) = TwistedExponentialElGamal::KeyGen(pp.enc_part); // generate a keypair

    newAcct.m = init_balance; 

    // initialize account balance with 0 coins
    BigInt r = Hash::StringToBigInt(newAcct.identity); 
    newAcct.balance_ct = TwistedExponentialElGamal::Enc(pp.enc_part, newAcct.pk, init_balance, r);

    #ifdef DEMO
        std::cout << identity << "'s ADCP account creation succeeds" << std::endl;
        newAcct.pk.Print("pk"); 
        std::cout << identity << "'s initial balance = "; 
        newAcct.m.PrintInDec(); 
        std::cout << std::endl;
        PrintSplitLine('-'); 
    #endif 

    return newAcct;
}

/* update Account if CTx is valid */
bool UpdateAccount(PP &pp, ToOneCTx &newCTx, Account &Acct_sender, Account &Acct_receiver)
{    
    std::cout << "update accounts >>>" << std::endl;
    
    TwistedExponentialElGamal::CT c_out; 
    c_out.X = newCTx.transfer_ct.vec_X[0]; c_out.Y = newCTx.transfer_ct.Y;
    TwistedExponentialElGamal::CT c_in; 
    c_in.X = newCTx.transfer_ct.vec_X[1]; c_in.Y = newCTx.transfer_ct.Y;

    // update sender's balance
    Acct_sender.balance_ct = TwistedExponentialElGamal::HomoSub(Acct_sender.balance_ct, c_out); 
    Acct_sender.m = TwistedExponentialElGamal::Dec(pp.enc_part, Acct_sender.sk, Acct_sender.balance_ct); 
    SaveAccount(Acct_sender, Acct_sender.identity+".account"); 

    // update receiver's balance
    Acct_receiver.balance_ct = TwistedExponentialElGamal::HomoAdd(Acct_receiver.balance_ct, c_in); 
    Acct_receiver.m = TwistedExponentialElGamal::Dec(pp.enc_part, Acct_receiver.sk, Acct_receiver.balance_ct);
    SaveAccount(Acct_receiver, Acct_receiver.identity+".account"); 
        
    return true; 
} 

/* reveal the balance */ 
BigInt RevealBalance(PP &pp, Account &Acct)
{
    return TwistedExponentialElGamal::Dec(pp.enc_part, Acct.sk, Acct.balance_ct); 
}

/* supervisor opens CTx */
BigInt SuperviseCTx(SP &sp, PP &pp, ToOneCTx &ctx)
{
    std::cout << "Supervise " << GetCTxFileName(ctx) << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 


    TwistedExponentialElGamal::CT ct; 
    ct.X = ctx.transfer_ct.vec_X[2];
    ct.Y = ctx.transfer_ct.Y;  
    BigInt v = TwistedExponentialElGamal::Dec(pp.enc_part, sp.ska, ct); 

    std::cout << ctx.pks.ToHexString() << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << ctx.pkr.ToHexString() << std::endl; 
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "supervising ctx takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return v; 
}

std::string ExtractToSignMessageFromCTx(ToOneCTx &newCTx)
{
    std::string str;
    str += newCTx.sn.ToHexString() + newCTx.pks.ToByteString() + newCTx.pkr.ToByteString(); 
    str += TwistedExponentialElGamal::CTToByteString(newCTx.sender_balance_ct);  
    str += TwistedExponentialElGamal::MRCTToByteString(newCTx.transfer_ct);   
    str += PlaintextEquality::ProofToByteString(newCTx.plaintext_equality_proof);  
    str += Bullet::ProofToByteString(newCTx.bullet_right_solvent_proof);   
    str += TwistedExponentialElGamal::CTToByteString(newCTx.refresh_sender_updated_balance_ct);  
    str += PlaintextKnowledge::ProofToByteString(newCTx.plaintext_knowledge_proof); 
    return str;
}

/* generate a confidential transaction: pk1 transfers v coins to pk2 */
ToOneCTx CreateCTx(PP &pp, Account &Acct_sender, BigInt &v, ECPoint &pkr)
{
    ToOneCTx newCTx; 
    size_t receiver_num = 1; 
    
    std::string ctx_type = "(1-to-1)"; 
    #ifdef DEMO
        std::cout << "begin to genetate " << ctx_type << " ctx >>>>>>" << std::endl; 
    #endif
    PrintSplitLine('-'); 

    #ifdef DEMO
        std::cout <<"1. generate memo info of ctx" << std::endl;  
    #endif

    auto start_time = std::chrono::steady_clock::now(); 

    std::string transcript_str = "";
    newCTx.sn = Acct_sender.sn;
    newCTx.pks = Acct_sender.pk; 
    newCTx.pkr = pkr; 

    std::vector<ECPoint> vec_pk = {newCTx.pks, newCTx.pkr, pp.pka}; 
    BigInt r = GenRandomBigIntLessThan(order);
    newCTx.transfer_ct = TwistedExponentialElGamal::Enc(pp.enc_part, vec_pk, v, r); 
    // TwistedExponentialElGamal::PrintCT(newCTx.transfer_ct); 

    #ifdef DEMO
        std::cout << "2. generate NIZKPoK for plaintext equality" << std::endl;  
    #endif

    // begin to generate NIZK proof for validity of ctx             
    PlaintextEquality::PP plaintext_equality_pp = PlaintextEquality::Setup(pp.enc_part); 
    
    PlaintextEquality::Instance plaintext_equality_instance;
     
    plaintext_equality_instance.vec_pk = {newCTx.pks, newCTx.pkr, pp.pka}; 
    plaintext_equality_instance.ct = newCTx.transfer_ct; 
    
    PlaintextEquality::Witness plaintext_equality_witness; 
    plaintext_equality_witness.r = r; 
    plaintext_equality_witness.v = v; 

    newCTx.plaintext_equality_proof = PlaintextEquality::Prove(plaintext_equality_pp, plaintext_equality_instance, plaintext_equality_witness, 
                             transcript_str);

    // PlaintextEquality::PrintProof(newCTx.plaintext_equality_proof); 

    #ifdef DEMO
        std::cout << "3. compute updated balance" << std::endl;  
    #endif
    // compute the updated balance

    TwistedExponentialElGamal::CT sender_updated_balance_ct; 
    newCTx.sender_balance_ct = Acct_sender.balance_ct;
    sender_updated_balance_ct.X = newCTx.sender_balance_ct.X - newCTx.transfer_ct.vec_X[0];
    sender_updated_balance_ct.Y = newCTx.sender_balance_ct.Y - newCTx.transfer_ct.Y;     

    #ifdef DEMO
        std::cout << "4. compute refreshed updated balance" << std::endl;  
    #endif
    // refresh the updated balance (with random coins r^*)
    BigInt r_star = GenRandomBigIntLessThan(order);    
    newCTx.refresh_sender_updated_balance_ct = TwistedExponentialElGamal::ReEnc(pp.enc_part, Acct_sender.pk, Acct_sender.sk, 
                                                                     sender_updated_balance_ct, r_star);

    #ifdef DEMO
        std::cout << "5. generate NIZKPoK for refreshed updated balance" << std::endl;  
    #endif
    PlaintextKnowledge::PP plaintext_knowledge_pp = PlaintextKnowledge::Setup(pp.enc_part);

    PlaintextKnowledge::Instance plaintext_knowledge_instance; 

    plaintext_knowledge_instance.pk = Acct_sender.pk; 
    plaintext_knowledge_instance.ct = newCTx.refresh_sender_updated_balance_ct; 
    
    PlaintextKnowledge::Witness plaintext_knowledge_witness; 
    plaintext_knowledge_witness.r = r_star; 
    plaintext_knowledge_witness.v = Acct_sender.m - v; 

    newCTx.plaintext_knowledge_proof = PlaintextKnowledge::Prove(plaintext_knowledge_pp, plaintext_knowledge_instance, plaintext_knowledge_witness, 
                              transcript_str); 

    #ifdef DEMO
        std::cout << "6. generate range proofs for transfer amount and updated balance" << std::endl;    
    #endif
    

    Bullet::Instance bullet_instance;
    bullet_instance.C = {newCTx.transfer_ct.Y, newCTx.refresh_sender_updated_balance_ct.Y};

    Bullet::Witness bullet_witness;  
    bullet_witness.r = {plaintext_equality_witness.r, plaintext_knowledge_witness.r}; 
    bullet_witness.v = {plaintext_equality_witness.v, plaintext_knowledge_witness.v};

    Bullet::Prove(pp.bullet_part, bullet_instance, bullet_witness, transcript_str, newCTx.bullet_right_solvent_proof); 

    #ifdef DEMO
        std::cout << "7. generate NIZKPoK for correct refreshing and authenticate the ctx" << std::endl;  
    #endif
    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOGEquality::PP dlog_equality_pp = DLOGEquality::Setup(); 
    
    DLOGEquality::Instance dlog_equality_instance; 
       
    dlog_equality_instance.g1 = sender_updated_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; // g1 = Y-Y^* = g^{r-r^*} 
    dlog_equality_instance.h1 = sender_updated_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; // h1 = X-X^* = pk^{r-r^*}
    
    dlog_equality_instance.g2 = pp.enc_part.g;                         // g2 = g
    dlog_equality_instance.h2 = Acct_sender.pk;                    // h2 = pk  
    DLOGEquality::Witness dlog_equality_witness;  
    dlog_equality_witness.w = Acct_sender.sk; 

    transcript_str += ExtractToSignMessageFromCTx(newCTx);
    newCTx.correct_refresh_proof = DLOGEquality::Prove(dlog_equality_pp, dlog_equality_instance, dlog_equality_witness, 
                        transcript_str); 

    #ifdef DEMO
        PrintSplitLine('-'); 
    #endif

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "ctx generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return newCTx; 
}

/* check if the given confidential transaction is valid */ 
bool VerifyCTx(PP &pp, ToOneCTx &newCTx)
{     
    std::string ctx_type = "(1-to-1)"; 
    #ifdef DEMO
        std::cout << "begin to verify "<< ctx_type << " ctx >>>>>>" << std::endl; 
    #endif

    auto start_time = std::chrono::steady_clock::now(); 
    
    bool Validity; 
    bool condition1, condition2, condition3, condition4; 

    std::string transcript_str = "";

    PlaintextEquality::PP plaintext_equality_pp = PlaintextEquality::Setup(pp.enc_part);

    PlaintextEquality::Instance plaintext_equality_instance; 
    plaintext_equality_instance.vec_pk = {newCTx.pks, newCTx.pkr, pp.pka};
    plaintext_equality_instance.ct = newCTx.transfer_ct;

    condition1 = PlaintextEquality::Verify(plaintext_equality_pp, plaintext_equality_instance, 
                                   transcript_str, newCTx.plaintext_equality_proof);
    #ifdef DEMO
        if (condition1) std::cout << "NIZKPoK for plaintext equality accepts" << std::endl; 
        else std::cout << "NIZKPoK for plaintext equality rejects" << std::endl; 
    #endif

    PlaintextKnowledge::PP plaintext_knowledge_pp = PlaintextKnowledge::Setup(pp.enc_part); 

    PlaintextKnowledge::Instance plaintext_knowledge_instance; 
    plaintext_knowledge_instance.pk = newCTx.pks; 
    plaintext_knowledge_instance.ct = newCTx.refresh_sender_updated_balance_ct;  

    condition2 = PlaintextKnowledge::Verify(plaintext_knowledge_pp, plaintext_knowledge_instance, 
                                    transcript_str, newCTx.plaintext_knowledge_proof);

    #ifdef DEMO
        if (condition2) std::cout << "NIZKPoK for refresh updated balance accepts" << std::endl; 
        else std::cout << "NIZKPoK for refresh updated balance rejects" << std::endl; 
    #endif

    // aggregated range proof for v and m-v lie in the right range 

    Bullet::Instance bullet_instance;
    bullet_instance.C = {newCTx.transfer_ct.Y, newCTx.refresh_sender_updated_balance_ct.Y};

    condition3 = Bullet::FastVerify(pp.bullet_part, bullet_instance, transcript_str, newCTx.bullet_right_solvent_proof); 

    #ifdef DEMO
        if (condition3) std::cout << "range proofs for transfer amount and updated balance accept" << std::endl; 
        else std::cout << "range proofs for transfer amount and updated balance reject" << std::endl;   
    #endif

    // check condition 4

    TwistedExponentialElGamal::CT updated_sender_balance_ct; 
    updated_sender_balance_ct.X = newCTx.sender_balance_ct.X - newCTx.transfer_ct.vec_X[0]; 
    updated_sender_balance_ct.Y = newCTx.sender_balance_ct.Y - newCTx.transfer_ct.Y; 

    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOGEquality::PP dlog_equality_pp = DLOGEquality::Setup();

    DLOGEquality::Instance dlog_equality_instance; 

    dlog_equality_instance.g1 = updated_sender_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; 
    dlog_equality_instance.h1 = updated_sender_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; 
    dlog_equality_instance.g2 = pp.enc_part.g; 
    dlog_equality_instance.h2 = newCTx.pks;  

    transcript_str += ExtractToSignMessageFromCTx(newCTx);
    condition4 = DLOGEquality::Verify(dlog_equality_pp, dlog_equality_instance, transcript_str, newCTx.correct_refresh_proof); 
    #ifdef DEMO
        if (condition4) std::cout << "NIZKPoK for refreshing correctness accepts and memo info is authenticated" << std::endl; 
        else std::cout << "NIZKPoK for refreshing correctness rejects or memo info is unauthenticated" << std::endl; 
    #endif


    Validity = condition1 && condition2 && condition3 && condition4; 

    std::string ctx_file = GetCTxFileName(newCTx); 
    #ifdef DEMO
        if (Validity) std::cout << ctx_file << " is valid <<<<<<" << std::endl; 
        else std::cout << ctx_file << " is invalid <<<<<<" << std::endl;
    #endif

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "ctx verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return Validity; 
}

/* check if a ctx is valid and update accounts if so */
bool Miner(PP &pp, ToOneCTx &newCTx, Account &Acct_sender, Account &Acct_receiver)
{
    if (newCTx.pks != Acct_sender.pk){
        std::cout << "sender does not match CTx" << std::endl; 
        return false; 
    }

    if (newCTx.pkr != Acct_receiver.pk){
        std::cout << "receiver does not match CTx" << std::endl; 
        return false; 
    }

    std::string ctx_file = GetCTxFileName(newCTx); 
    if(VerifyCTx(pp, newCTx) == true){
        UpdateAccount(pp, newCTx, Acct_sender, Acct_receiver);
        SaveCTx(newCTx, ctx_file);  
        std::cout << ctx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << ctx_file << " is discarded" << std::endl; 
        return false; 
    }
}


/* support more policies */

struct LimitPolicy{
    BigInt LEFT_BOUND;  // the transfer limit 
    BigInt RIGHT_BOUND; 
};

struct RatePolicy{
    BigInt t1, t2;  // the tax rate = t1/t2
};

struct OpenPolicy{
    BigInt v;   // the hidden value = v
}; 


/* generate a NIZK proof for CT = Enc(pk, v; r)  */
DLOGEquality::Proof JustifyPolicy(PP &pp, Account &Acct_user, ToOneCTx &doubtCTx, OpenPolicy &policy)
{
    if ((Acct_user.pk != doubtCTx.pks) && (Acct_user.pk != doubtCTx.pkr)) {
        std::cerr << "the identity of claimer does not match ctx" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    DLOGEquality::PP dlogeq_pp = DLOGEquality::Setup();

    DLOGEquality::Instance dlogeq_instance;  
    
    dlogeq_instance.g1 = doubtCTx.transfer_ct.Y - pp.enc_part.h * policy.v; // g1 = g^r h^v - h^v = g^r
    dlogeq_instance.g2 = pp.enc_part.g; 
    if (Acct_user.pk == doubtCTx.pks){
        dlogeq_instance.h1 = doubtCTx.transfer_ct.vec_X[0]; // pk1^r
        dlogeq_instance.h2 = doubtCTx.pks;  
    }
    else{
        dlogeq_instance.h1 = doubtCTx.transfer_ct.vec_X[1];  // pk2^r
        dlogeq_instance.h2 = doubtCTx.pkr;  
    }
    DLOGEquality::Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_user.sk; 

    std::string transcript_str = ""; 
    DLOGEquality::Proof open_proof = DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str); 
    
    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for open policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return open_proof; 
} 

/* check if the proposed NIZK proof PI for open policy is valid */ 
bool AuditPolicy(PP &pp, Account &Acct_user, ToOneCTx &doubtCTx,  
                 OpenPolicy &policy, DLOGEquality::Proof &open_proof)
{ 
    if ((Acct_user.pk != doubtCTx.pks) && (Acct_user.pk != doubtCTx.pkr)){
        std::cout << "the identity of claimer does not match ctx" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    DLOGEquality::PP dlogeq_pp = DLOGEquality::Setup(); 

    DLOGEquality::Instance dlogeq_instance; 
    dlogeq_instance.g1 = doubtCTx.transfer_ct.Y - pp.enc_part.h * policy.v;  // g1 = g^r h^v - h^v = g^r
    dlogeq_instance.g2 = pp.enc_part.g;
    if (Acct_user.pk == doubtCTx.pks){
        dlogeq_instance.h1 = doubtCTx.transfer_ct.vec_X[0];
        dlogeq_instance.h2 = doubtCTx.pks;  
    }
    else{
        dlogeq_instance.h1 = doubtCTx.transfer_ct.vec_X[1];
        dlogeq_instance.h2 = doubtCTx.pkr;  
    }
    bool validity;

    std::string transcript_str = "";
    validity = DLOGEquality::Verify(dlogeq_pp, dlogeq_instance, transcript_str, open_proof); 

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "verify NIZK proof for open policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    if(validity == true){
        std::cout << "open policy auditing succeeds" << std::endl;
    } 
    else{
        std::cout << "open policy auditing fails" << std::endl;
    }

    return validity; 
}


/* 
    generate NIZK proof for rate policy: CT = Enc(pk, v1) && CT = Enc(pk, v2) 
    v2/v1 = t1/t2
*/
DLOGEquality::Proof JustifyPolicy(PP &pp, Account &Acct_user, ToOneCTx &ctx1, ToOneCTx &ctx2, RatePolicy &policy)
{
    if (Acct_user.pk != ctx1.pkr || Acct_user.pk != ctx2.pks){
        std::cerr << "the identity of claimer does not match" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    
    DLOGEquality::PP dlogeq_pp = DLOGEquality::Setup();

    DLOGEquality::Instance dlogeq_instance; 
    dlogeq_instance.g1 = pp.enc_part.g;     // g1 = g 
    dlogeq_instance.h1 = Acct_user.pk; // g2 = pk = g^sk

    TwistedExponentialElGamal::CT ct_in; 
    ct_in.X = ctx1.transfer_ct.vec_X[1]; 
    ct_in.Y = ctx1.transfer_ct.Y; 
    ct_in = TwistedExponentialElGamal::ScalarMul(ct_in, policy.t1); 
    
    TwistedExponentialElGamal::CT ct_out; 
    ct_out.X = ctx2.transfer_ct.vec_X[0]; 
    ct_out.Y = ctx2.transfer_ct.Y; 
    ct_out = TwistedExponentialElGamal::ScalarMul(ct_out, policy.t2); 

    TwistedExponentialElGamal::CT ct_diff = TwistedExponentialElGamal::HomoSub(ct_in, ct_out);  

    dlogeq_instance.g2 = ct_diff.Y; 
    dlogeq_instance.h2 = ct_diff.X; 

    DLOGEquality::Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_user.sk; 

    std::string transcript_str = ""; 
    DLOGEquality::Proof rate_proof = DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str); 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for rate policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return rate_proof; 
} 

/* check if the NIZK proof PI for rate policy is valid */
bool AuditPolicy(PP &pp, ECPoint pk, ToOneCTx &ctx1, ToOneCTx &ctx2,  
                 RatePolicy &policy, DLOGEquality::Proof &rate_proof)
{ 
    if ((pk != ctx1.pkr) || (pk != ctx2.pks)){
        std::cout << "the identity of claimer does not match" << std::endl; 
        return false; 
    }
    
    auto start_time = std::chrono::steady_clock::now(); 
    
    DLOGEquality::PP dlogeq_pp = DLOGEquality::Setup(); 

    DLOGEquality::Instance dlogeq_instance; 
    dlogeq_instance.g1 = pp.enc_part.g;     // g1 = g 
    dlogeq_instance.h1 = pk; // g2 = pk = g^sk

    TwistedExponentialElGamal::CT ct_in; 
    ct_in.X = ctx1.transfer_ct.vec_X[1]; 
    ct_in.Y = ctx1.transfer_ct.Y; 
    ct_in = TwistedExponentialElGamal::ScalarMul(ct_in, policy.t1); 
    
    TwistedExponentialElGamal::CT ct_out; 
    ct_out.X = ctx2.transfer_ct.vec_X[0]; 
    ct_out.Y = ctx2.transfer_ct.Y; 
    ct_out = TwistedExponentialElGamal::ScalarMul(ct_out, policy.t2);  

    TwistedExponentialElGamal::CT ct_diff = TwistedExponentialElGamal::HomoSub(ct_in, ct_out);  

    dlogeq_instance.g2 = ct_diff.Y; 
    dlogeq_instance.h2 = ct_diff.X; 

    std::string transcript_str = ""; 
    bool validity = DLOGEquality::Verify(dlogeq_pp, dlogeq_instance, transcript_str, rate_proof); 

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "verify NIZK proof for rate policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    if(validity == true){
        std::cout << "rate policy auditing succeeds" << std::endl;
    } 
    else{
        std::cout << "rate policy auditing fails" << std::endl;
    }

    return validity; 
}

/*
    sender prove an encrypted value C = Enc(pk, m; r) lie in the right range 
    prover knows m and r
*/


/*  generate a NIZK proof for limit predicate */
bool JustifyPolicy(PP &pp, Account &Acct_user, std::vector<ToOneCTx> &ctx_set, 
                   LimitPolicy &policy, Gadget::Proof_type2 &limit_proof)
{
    for(auto i = 0; i < ctx_set.size(); i++){
        if (Acct_user.pk != ctx_set[i].pks){
            std::cout << "the identity of claimer does not match" << std::endl; 
            return false; 
        }
    }

    auto start_time = std::chrono::steady_clock::now(); 

    TwistedExponentialElGamal::CT ct_sum;
    ct_sum.X.SetInfinity();
    ct_sum.Y.SetInfinity(); 
    TwistedExponentialElGamal::CT ct_temp; 
    for(auto i = 0; i < ctx_set.size(); i++)
    {
        ct_temp.X = ctx_set[i].transfer_ct.vec_X[0]; 
        ct_temp.Y = ctx_set[i].transfer_ct.Y;
        ct_sum = TwistedExponentialElGamal::HomoAdd(ct_sum, ct_temp); 
    } 
 
    Gadget::PP gadget_pp = Gadget::Setup(pp.enc_part, pp.bullet_part);
    Gadget::Instance instance; 
    instance.pk = Acct_user.pk; 
    instance.ct.X = ct_sum.X; instance.ct.Y = ct_sum.Y;  
    Gadget::Witness_type2 witness;
    witness.sk = Acct_user.sk;  

    std::string transcript_str = ""; 

    Gadget::Prove(gadget_pp, instance, policy.LEFT_BOUND, policy.RIGHT_BOUND, witness, transcript_str, limit_proof); 
    
    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for limit policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return true;
} 

/* check if the proposed NIZK proof for limit policy is valid */ 
bool AuditPolicy(PP &pp, ECPoint pk, std::vector<ToOneCTx> &ctx_set, 
                 LimitPolicy &policy, Gadget::Proof_type2 &limit_proof)
{ 
    for(auto i = 0; i < ctx_set.size(); i++){
        if (pk != ctx_set[i].pks){
            std::cout << "the identity of claimer does not match" << std::endl; 
            return false; 
        }
    }

    auto start_time = std::chrono::steady_clock::now(); 

    TwistedExponentialElGamal::CT ct_sum;
    ct_sum.X.SetInfinity();
    ct_sum.Y.SetInfinity(); 
    TwistedExponentialElGamal::CT ct_temp; 
    for(auto i = 0; i < ctx_set.size(); i++)
    {
        ct_temp.X = ctx_set[i].transfer_ct.vec_X[0]; 
        ct_temp.Y = ctx_set[i].transfer_ct.Y;
        ct_sum = TwistedExponentialElGamal::HomoAdd(ct_sum, ct_temp); 
    } 
 
    Gadget::PP gadget_pp = Gadget::Setup(pp.enc_part, pp.bullet_part);
    Gadget::Instance instance; 
    instance.pk = pk; 
    instance.ct.X = ct_sum.X; instance.ct.Y = ct_sum.Y; 

    std::string transcript_str = ""; 

    bool validity = Gadget::Verify(gadget_pp, instance,  policy.LEFT_BOUND, policy.RIGHT_BOUND, transcript_str, limit_proof); 

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "verify NIZK proof for limit policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    if(validity == true){
        std::cout << "limit policy auditing succeeds" << std::endl;
    } 
    else{
        std::cout << "limit policy auditing fails" << std::endl;
    }

    return validity; 
}


/* 
** support oen to many transactions 
*/

// define the structure for confidential transaction
struct ToManyCTx{
    BigInt sn;                        // serial number: uniquely defines a transaction
    // memo information
    TwistedExponentialElGamal::CT sender_balance_ct;        // the current balance of pk1 (not necessarily included)
    ECPoint pks;      // sender = pks
    TwistedExponentialElGamal::CT sender_transfer_ct;
    std::vector<ECPoint> vec_pkr;  
    std::vector<TwistedExponentialElGamal::MRCT> vec_receiver_transfer_ct;    // (X0 = pka^r, X1 = pkr^r, Y = g^r h^v)  

    // validity proof
    TwistedExponentialElGamal::CT refresh_sender_updated_balance_ct;  // fresh encryption of updated balance (randomness is known)
    PlaintextKnowledge::Proof plaintext_knowledge_proof; // NIZKPoK for refresh ciphertext (X^*, Y^*)
    DLOGEquality::Proof correct_refresh_proof;     // fresh updated balance is correct

    std::vector<PlaintextEquality::Proof> vec_plaintext_equality_proof;     // NIZKPoK for transfer ciphertext (X1, X2, Y)
    Bullet::Proof bullet_right_solvent_proof;   // aggregated range proof for v, m-v and v_i lie in the right range 

    DLOGKnowledge::Proof balance_proof; // prove v = v_1 +...+ v_n    
};

// save CTx into sn.ctx file
void SaveCTx(ToManyCTx &newCTx, std::string ADCP_CTx_File)
{
    std::ofstream fout; 
    fout.open(ADCP_CTx_File, std::ios::binary); 
    
    // save sn
    fout << newCTx.sn; 
     
    // save memo info
    fout << newCTx.pks;
    fout << newCTx.sender_transfer_ct;

    for(auto i = 0; i < newCTx.vec_pkr.size(); i++){
        fout << newCTx.vec_pkr[i];
    }
    for(auto i = 0; i < newCTx.vec_receiver_transfer_ct.size(); i++){
        fout << newCTx.vec_receiver_transfer_ct[i];
    } 
    
    // save proofs
    for(auto i = 0; i < newCTx.vec_plaintext_equality_proof.size(); i++){
        fout << newCTx.vec_plaintext_equality_proof[i];
    }
    fout << newCTx.refresh_sender_updated_balance_ct; 
    fout << newCTx.correct_refresh_proof; 
    fout << newCTx.bullet_right_solvent_proof; 
    fout << newCTx.plaintext_knowledge_proof; 

    fout.close();

    // calculate the size of ctx_file
    std::ifstream fin; 
    fin.open(ADCP_CTx_File, std::ios::ate | std::ios::binary);
    std::cout << ADCP_CTx_File << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
}

std::string ExtractToSignMessageFromCTx(ToManyCTx &newCTx)
{
    std::string str;
    str += newCTx.sn.ToHexString() + newCTx.pks.ToByteString(); 
    for(auto i = 0; i < newCTx.vec_pkr.size(); i++){
        str += newCTx.vec_pkr[i].ToByteString();
    }

    str += TwistedExponentialElGamal::CTToByteString(newCTx.sender_balance_ct);  
    str += TwistedExponentialElGamal::CTToByteString(newCTx.sender_transfer_ct);  
    for(auto i = 0; i < newCTx.vec_receiver_transfer_ct.size(); i++){
        str += TwistedExponentialElGamal::MRCTToByteString(newCTx.vec_receiver_transfer_ct[i]);
    }

    for(auto i = 0; i < newCTx.vec_plaintext_equality_proof.size(); i++){
        str += PlaintextEquality::ProofToByteString(newCTx.vec_plaintext_equality_proof[i]);  
    }
   
    str += Bullet::ProofToByteString(newCTx.bullet_right_solvent_proof);   
    str += TwistedExponentialElGamal::CTToByteString(newCTx.refresh_sender_updated_balance_ct);  
    str += PlaintextKnowledge::ProofToByteString(newCTx.plaintext_knowledge_proof); 

    str += DLOGKnowledge::ProofToByteString(newCTx.balance_proof); 

    return str;
}

/* 
* generate a confidential transaction: pks transfers vi coins to pkr[i] 
*/
ToManyCTx CreateCTx(PP &pp, Account &Acct_sender, std::vector<BigInt> &vec_v, std::vector<ECPoint> &vec_pkr)
{ 
    ToManyCTx newCTx; 
    size_t n = vec_v.size(); 
    if(IsPowerOfTwo(n+1) == false){
        std::cerr << "receiver num must be 2^n-1" << std::endl;
    }

    std::string ctx_type = "(1-to-"+std::to_string(n)+")"; 

    #ifdef DEMO
        std::cout << "begin to genetate " << ctx_type << " ctx >>>>>>" << std::endl; 
    #endif
    PrintSplitLine('-'); 

    #ifdef DEMO
        std::cout <<"1. generate memo info of ctx" << std::endl;  
    #endif

    auto start_time = std::chrono::steady_clock::now();

    std::string transcript_str = "";  
    newCTx.sn = Acct_sender.sn;
    newCTx.pks = Acct_sender.pk; 
    newCTx.vec_pkr = vec_pkr; 

    BigInt v = bn_0;
    for(auto i = 0; i < n; i++){
        v += vec_v[i]; 
    }

    BigInt r; 
    r = GenRandomBigIntLessThan(order); 
    newCTx.sender_transfer_ct = TwistedExponentialElGamal::Enc(pp.enc_part, newCTx.pks, v, r); 

    std::vector<ECPoint> vec_pk(2); 
    std::vector<BigInt> vec_r(n); 
    newCTx.vec_receiver_transfer_ct.resize(n); 
    for(auto i = 0; i < n; i++){
        vec_pk[0] = vec_pkr[i];
        vec_pk[1] = pp.pka;
        vec_r[i] = GenRandomBigIntLessThan(order);
        newCTx.vec_receiver_transfer_ct[i] = TwistedExponentialElGamal::Enc(pp.enc_part, vec_pk, vec_v[i], vec_r[i]); 
    }

    #ifdef DEMO
        std::cout << "2. generate NIZKPoK for plaintext equality" << std::endl;  
    #endif

    // generate NIZK proof for validity of transfer              
    PlaintextEquality::PP plaintext_equality_pp = PlaintextEquality::Setup(pp.enc_part); 
    
    PlaintextEquality::Instance plaintext_equality_instance;
    PlaintextEquality::Witness plaintext_equality_witness; 
    newCTx.vec_plaintext_equality_proof.resize(n);  
    for(auto i = 0; i < n; i++){
        plaintext_equality_instance.vec_pk = {vec_pkr[i], pp.pka}; 
        plaintext_equality_instance.ct = newCTx.vec_receiver_transfer_ct[i]; 
        plaintext_equality_witness.r = vec_r[i]; 
        plaintext_equality_witness.v = vec_v[i]; 
        newCTx.vec_plaintext_equality_proof[i] = PlaintextEquality::Prove(plaintext_equality_pp, plaintext_equality_instance, 
                                 plaintext_equality_witness, transcript_str);
    }

    #ifdef DEMO
        std::cout << "3. compute updated balance" << std::endl;  
    #endif
    // compute the updated balance
    newCTx.sender_balance_ct = Acct_sender.balance_ct; 
    TwistedExponentialElGamal::CT sender_updated_balance_ct = TwistedExponentialElGamal::HomoSub(newCTx.sender_balance_ct, newCTx.sender_transfer_ct);
  

    #ifdef DEMO
        std::cout << "4. compute refreshed updated balance" << std::endl;  
    #endif

    // refresh the updated balance (with random coins r^*)
    BigInt r_star = GenRandomBigIntLessThan(order);    
    newCTx.refresh_sender_updated_balance_ct = TwistedExponentialElGamal::ReEnc(pp.enc_part, Acct_sender.pk, Acct_sender.sk, 
                                                                     sender_updated_balance_ct, r_star);

    #ifdef DEMO
        std::cout << "5. generate NIZKPoK for refreshed updated balance" << std::endl;  
    #endif
    PlaintextKnowledge::PP plaintext_knowledge_pp = PlaintextKnowledge::Setup(pp.enc_part);
    PlaintextKnowledge::Instance plaintext_knowledge_instance; 

    plaintext_knowledge_instance.pk = Acct_sender.pk; 
    plaintext_knowledge_instance.ct = newCTx.refresh_sender_updated_balance_ct; 
    
    PlaintextKnowledge::Witness plaintext_knowledge_witness; 
    plaintext_knowledge_witness.r = r_star; 
    plaintext_knowledge_witness.v = Acct_sender.m - v; 

    newCTx.plaintext_knowledge_proof = PlaintextKnowledge::Prove(plaintext_knowledge_pp, plaintext_knowledge_instance, plaintext_knowledge_witness, 
                              transcript_str); 


    #ifdef DEMO
        std::cout << "6. generate range proofs for transfer amount and updated balance" << std::endl;    
    #endif
    
    // aggregated range proof for v and m-v lie in the right range 

    Bullet::Instance bullet_instance;
    Bullet::Witness bullet_witness;  
    for(auto i = 0; i < n; i++){
        bullet_instance.C.emplace_back(newCTx.vec_receiver_transfer_ct[i].Y);
        bullet_witness.r.emplace_back(vec_r[i]); 
        bullet_witness.v.emplace_back(vec_v[i]); 
    }

    bullet_instance.C.emplace_back(newCTx.refresh_sender_updated_balance_ct.Y);

    bullet_witness.r.emplace_back(plaintext_knowledge_witness.r); 
    bullet_witness.v.emplace_back(plaintext_knowledge_witness.v);

    Bullet::Prove(pp.bullet_part, bullet_instance, bullet_witness, transcript_str, newCTx.bullet_right_solvent_proof); 

    #ifdef DEMO
        std::cout << "7. generate NIZKPoK for v = v_1+...+v_n" << std::endl;    
    #endif
    DLOGKnowledge::PP dlog_knowledge_pp = DLOGKnowledge::Setup();

    DLOGKnowledge::Instance dlog_knowledge_instance;
    dlog_knowledge_instance.g = pp.enc_part.g; 
    dlog_knowledge_instance.h = newCTx.sender_transfer_ct.Y; 
    for(auto i = 0; i < n; i++){
        dlog_knowledge_instance.h -= newCTx.vec_receiver_transfer_ct[i].Y; 
    } 
    DLOGKnowledge::Witness dlog_knowledge_witness; 
    dlog_knowledge_witness.w = r; 
    for(auto i = 0; i < n; i++){
        dlog_knowledge_witness.w -= vec_r[i]; 
    }

    newCTx.balance_proof = DLOGKnowledge::Prove(dlog_knowledge_pp, dlog_knowledge_instance, dlog_knowledge_witness, 
                         transcript_str);

    #ifdef DEMO
        std::cout << "8. generate NIZKPoK for correct refreshing and authenticate the ctx" << std::endl;  
    #endif
    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOGEquality::PP dlog_equality_pp = DLOGEquality::Setup();  

    DLOGEquality::Instance dlog_equality_instance; 
       
    dlog_equality_instance.g1 = sender_updated_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; // g1 = Y-Y^* = g^{r-r^*} 
    dlog_equality_instance.h1 = sender_updated_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; // h1 = X-X^* = pk^{r-r^*}
    
    dlog_equality_instance.g2 = pp.enc_part.g;                     // g2 = g
    dlog_equality_instance.h2 = Acct_sender.pk;                    // h2 = pk  
    DLOGEquality::Witness dlog_equality_witness;  
    dlog_equality_witness.w = Acct_sender.sk; 

    transcript_str += ExtractToSignMessageFromCTx(newCTx); 
    newCTx.correct_refresh_proof = DLOGEquality::Prove(dlog_equality_pp, dlog_equality_instance, dlog_equality_witness, 
                        transcript_str); 

    #ifdef DEMO
        PrintSplitLine('-'); 
    #endif

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << ctx_type << " ctx generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return newCTx; 
}

/* check if the given confidential transaction is valid */ 
bool VerifyCTx(PP &pp, ToManyCTx &newCTx)
{     
    size_t n = newCTx.vec_pkr.size(); 
    if(IsPowerOfTwo(n+1) == false){
        std::cerr << "receiver num must be 2^n-1" << std::endl;
    }
    std::string ctx_type = "(1-to-"+std::to_string(n)+")"; 
    
    #ifdef DEMO
        std::cout << "begin to verify " <<ctx_type << " ctx >>>>>>" << std::endl; 
    #endif

    std::string transcript_str = "";


    auto start_time = std::chrono::steady_clock::now(); 

    // generate NIZK proof for validity of transfer              
    bool condition1 = true;      
    
    PlaintextEquality::PP plaintext_equality_pp = PlaintextEquality::Setup(pp.enc_part); 
    PlaintextEquality::Instance plaintext_equality_instance;
    for(auto i = 0; i < n; i++){
        plaintext_equality_instance.vec_pk = {newCTx.vec_pkr[i], pp.pka}; 
        plaintext_equality_instance.ct = newCTx.vec_receiver_transfer_ct[i]; 
        if(PlaintextEquality::Verify(plaintext_equality_pp, plaintext_equality_instance, 
                                     transcript_str, newCTx.vec_plaintext_equality_proof[i]) == false){
            condition1 = false;
        }
    }
    
    #ifdef DEMO
        if (condition1) std::cout << "NIZKPoK for plaintext equality accepts" << std::endl; 
        else std::cout << "NIZKPoK for plaintext equality rejects" << std::endl; 
    #endif

    // check V2
    bool condition2; 
    
    PlaintextKnowledge::PP plaintext_knowledge_pp = PlaintextKnowledge::Setup(pp.enc_part); 

    PlaintextKnowledge::Instance plaintext_knowledge_instance; 
    plaintext_knowledge_instance.pk = newCTx.pks; 
    plaintext_knowledge_instance.ct = newCTx.refresh_sender_updated_balance_ct;  

    condition2 = PlaintextKnowledge::Verify(plaintext_knowledge_pp, plaintext_knowledge_instance, 
                                            transcript_str, newCTx.plaintext_knowledge_proof);

    #ifdef DEMO
        if (condition2) std::cout << "NIZKPoK for refresh updated balance accepts" << std::endl; 
        else std::cout << "NIZKPoK for refresh updated balance rejects" << std::endl; 
    #endif

    // check range proof
    bool condition3; 

    Bullet::Instance bullet_instance; 
    for(auto i = 0; i < n; i++){
        bullet_instance.C.emplace_back(newCTx.vec_receiver_transfer_ct[i].Y);
    }

    bullet_instance.C.emplace_back(newCTx.refresh_sender_updated_balance_ct.Y);
    condition3 = Bullet::FastVerify(pp.bullet_part, bullet_instance, transcript_str, newCTx.bullet_right_solvent_proof); 

    #ifdef DEMO
        if (condition3) std::cout << "range proofs for transfer amount and updated balance accept" << std::endl; 
        else std::cout << "range proofs for transfer amount and updated balance reject" << std::endl; 
    #endif

    // check balance proof
    bool condition4;

    DLOGKnowledge::PP dlog_knowledge_pp = DLOGKnowledge::Setup();

    DLOGKnowledge::Instance dlog_knowledge_instance;
    dlog_knowledge_instance.g = pp.enc_part.g; 
    dlog_knowledge_instance.h = newCTx.sender_transfer_ct.Y; 
    for(auto i = 0; i < n; i++){
        dlog_knowledge_instance.h -= newCTx.vec_receiver_transfer_ct[i].Y; 
    } 

    condition4 = DLOGKnowledge::Verify(dlog_knowledge_pp, dlog_knowledge_instance, transcript_str, newCTx.balance_proof);

    #ifdef DEMO
        if (condition4) std::cout << "NIZKPoK for balance proof accepts" << std::endl; 
        else std::cout << "NIZKPoK for balance proof rejects" << std::endl; 
    #endif

    // check the NIZK proof for refresh correctness
    bool condition5;
    DLOGEquality::PP dlog_equality_pp = DLOGEquality::Setup(); 

    DLOGEquality::Instance dlog_equality_instance; 

    TwistedExponentialElGamal::CT sender_updated_balance_ct = TwistedExponentialElGamal::HomoSub(newCTx.sender_balance_ct, newCTx.sender_transfer_ct);

    dlog_equality_instance.g1 = sender_updated_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; 
    dlog_equality_instance.h1 = sender_updated_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; 
    dlog_equality_instance.g2 = pp.enc_part.g; 
    dlog_equality_instance.h2 = newCTx.pks;  

    transcript_str += ExtractToSignMessageFromCTx(newCTx);
    condition5 = DLOGEquality::Verify(dlog_equality_pp, dlog_equality_instance, 
                                      transcript_str, newCTx.correct_refresh_proof); 

    #ifdef DEMO
        if (condition5) std::cout << "NIZKPoK for refreshing correctness accepts and ctx is authenticated" << std::endl; 
        else std::cout << "NIZKPoK for refreshing correctness rejects or ctx is unauthenticated" << std::endl; 
    #endif

    bool Validity = condition1 && condition2 && condition3 && condition4 && condition5; 

    std::string ctx_file = GetCTxFileName(newCTx); 
    #ifdef DEMO
        if (Validity) std::cout << ctx_file << " is valid <<<<<<" << std::endl; 
        else std::cout << ctx_file << " is invalid <<<<<<" << std::endl;
    #endif

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << ctx_type << " ctx verification takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return Validity; 
}


/* print the details of a confidential to-many-transaction */
void PrintCTx(ToManyCTx &newCTx)
{
    PrintSplitLine('-');
    std::string ctx_file = GetCTxFileName(newCTx);  
    std::cout << ctx_file << " content >>>>>>" << std::endl; 

    std::cout << "current sender balance >>>" << std::endl; 
    TwistedExponentialElGamal::PrintCT(newCTx.sender_balance_ct);
    std::cout << std::endl; 

    newCTx.pks.Print("sender's public key"); 
    std::cout << "receiver's public key" << std::endl;
    PrintECPointVector(newCTx.vec_pkr, "pkr");
    std::cout << std::endl;  


    std::cout << "sender's transfer ct >>>" << std::endl;
    TwistedExponentialElGamal::PrintCT(newCTx.sender_transfer_ct);
    std::cout << std::endl;

    std::cout << "receiver's transfer ct >>>" << std::endl; 
    for(auto i = 0; i < newCTx.vec_receiver_transfer_ct.size(); i++){
        TwistedExponentialElGamal::PrintCT(newCTx.vec_receiver_transfer_ct[i]); 
        std::cout << std::endl;
    } 

    std::cout << "NIZKPoK for plaintext equality of receiver's ct >>>" << std::endl; 
    for(auto i = 0; i < newCTx.vec_plaintext_equality_proof.size(); i++){
        PlaintextEquality::PrintProof(newCTx.vec_plaintext_equality_proof[i]); 
    }
    std::cout << std::endl; 

    std::cout << "NIZKPoK for input-output balance >>> " << std::endl; 
    DLOGKnowledge::PrintProof(newCTx.balance_proof); // prove v = v_1 +...+ v_n 
    std::cout << std::endl;

    std::cout << "range proofs for transfer amount and updated balance >>> " << std::endl; 
    Bullet::PrintProof(newCTx.bullet_right_solvent_proof); 
    std::cout << std::endl;

    std::cout << "refresh updated balance >>>" << std::endl;
    TwistedExponentialElGamal::PrintCT(newCTx.refresh_sender_updated_balance_ct); 
    std::cout << std::endl;

    std::cout << "NIZKPoK of refresh updated balance >>>" << std::endl; 
    PlaintextKnowledge::PrintProof(newCTx.plaintext_knowledge_proof); 
    std::cout << std::endl;
    
    std::cout << "NIZKPoK for refreshing correctness >>>" << std::endl; 
    DLOGEquality::PrintProof(newCTx.correct_refresh_proof);     // fresh updated balance is correct
    std::cout << std::endl;

    PrintSplitLine('-'); 
}

/* update Account if CTx is valid */
bool UpdateAccount(PP &pp, ToManyCTx &newCTx, Account &Acct_sender, std::vector<Account> &vec_Acct_receiver)
{    
    Acct_sender.sn = Acct_sender.sn + bn_1;

    // update sender's balance
    Acct_sender.balance_ct = TwistedExponentialElGamal::HomoSub(Acct_sender.balance_ct, newCTx.sender_transfer_ct); 
    Acct_sender.m = TwistedExponentialElGamal::Dec(pp.enc_part, Acct_sender.sk, Acct_sender.balance_ct); 
    SaveAccount(Acct_sender, Acct_sender.identity+".account"); 

    TwistedExponentialElGamal::CT c_in; 
    for(auto i = 0; i < vec_Acct_receiver.size(); i++){
        c_in.X = newCTx.vec_receiver_transfer_ct[i].vec_X[0]; 
        c_in.Y = newCTx.vec_receiver_transfer_ct[i].Y;
        // update receiver's balance
        vec_Acct_receiver[i].balance_ct = TwistedExponentialElGamal::HomoAdd(vec_Acct_receiver[i].balance_ct, c_in); 
        vec_Acct_receiver[i].m = TwistedExponentialElGamal::Dec(pp.enc_part, vec_Acct_receiver[i].sk, vec_Acct_receiver[i].balance_ct);
        SaveAccount(vec_Acct_receiver[i], vec_Acct_receiver[i].identity+".account"); 
    }

    return true; 
} 


/* check if a ctx is valid and update accounts if so */
bool Miner(PP &pp, ToManyCTx &newCTx, Account &Acct_sender, std::vector<Account> &vec_Acct_receiver)
{
    if (newCTx.pks != Acct_sender.pk){
        std::cout << "sender does not match CTx" << std::endl; 
        return false; 
    }
    for(auto i = 0; i < vec_Acct_receiver.size(); i++){
        if (newCTx.vec_pkr[i] != vec_Acct_receiver[i].pk){
            std::cerr << i<<"-th receiver does not match ctx" << std::endl; 
            return false;
        } 
    }

    std::string ctx_file = GetCTxFileName(newCTx); 
    if(VerifyCTx(pp, newCTx) == true){
        UpdateAccount(pp, newCTx, Acct_sender, vec_Acct_receiver);
        SaveCTx(newCTx, ctx_file);  
        std::cout << ctx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << ctx_file << " is discarded" << std::endl; 
        return false; 
    }
}


/* supervisor opens CTx */
std::vector<BigInt> SuperviseCTx(SP &sp, PP &pp, ToManyCTx &ctx)
{
    size_t n = ctx.vec_pkr.size();
    std::vector<BigInt> vec_v(n); 

    std::cout << "Supervise " << GetCTxFileName(ctx) << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 

    std::cout << ctx.pks.ToHexString() << " transfers "; 
    std::cout << std::endl;
    TwistedExponentialElGamal::CT ct; 
    for(auto i = 0; i < n; i++){
        ct.X = ctx.vec_receiver_transfer_ct[i].vec_X[1];
        ct.Y = ctx.vec_receiver_transfer_ct[i].Y;  
        vec_v[i] = TwistedExponentialElGamal::Dec(pp.enc_part, sp.ska, ct);
        std::cout << BN_bn2dec(vec_v[i].bn_ptr) << " coins to " << ctx.vec_pkr[i].ToHexString() << std::endl; 
    } 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "supervising ctx takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return vec_v; 
}

}

#endif
