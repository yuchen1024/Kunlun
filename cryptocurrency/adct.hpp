/****************************************************************************
this hpp implements the ADCT functionality 
*****************************************************************************/
#ifndef CRYPTOCURRENCY_ADCT_HPP_
#define CRYPTOCURRENCY_ADCT_HPP_

#include "../pke/twisted_elgamal.hpp"        // implement Twisted ElGamal  
#include "../nizk/nizk_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../nizk/nizk_plaintext_knowledge.hpp"        // NIZKPoK for ciphertext/honest encryption 
#include "../nizk/nizk_dlog_equality.hpp"      // NIZKPoK for dlog equality
#include "../bulletproofs/bullet_proof.hpp"    // implement Log Size Bulletproof
#include "../gadget/range_proof.hpp"

#define DEMO           // demo mode 
//#define DEBUG        // show debug information 

namespace ADCT{
// define the structure of system parameters
struct PP{
    size_t RANGE_LEN; // the maximum coin value is 2^RANGE_LEN 
    size_t LOG_RANGE_LEN; // this parameter will be used by Bulletproof
    size_t AGG_NUM;    // number of aggregated proofs (for now, we require m to be the power of 2)
    size_t SN_LEN;    // sn length
    size_t TRADEOFF_NUM; // used for fast decryption 
    size_t DEC_THREAD_NUM; // used by twisted ElGamal 

    BigInt MAXIMUM_COINS; 

    ECPoint g; 
    ECPoint h;
    ECPoint u; // used for inside innerproduct statement
    std::vector<ECPoint> vec_g; 
    std::vector<ECPoint> vec_h; // the pp of innerproduct part  

    ECPoint pk_a; // supervisor's pk
    BigInt sk_a;   // supervisor's sk
};

// define the structure of system parameters
struct SP{
    BigInt sk_a;   // supervisor's sk
};

struct Account{
    std::string identity;     // id
    ECPoint pk;              // public key
    BigInt sk;              // secret key
    TwistedElGamal::CT balance_ct;  // current balance
    BigInt m;               // dangerous (should only be used for speeding up the proof generation)
    BigInt sn; 
};

// define the structure for confidential transaction
struct CTx{
    BigInt sn;                        // serial number: uniquely defines a transaction
    // memo information
    TwistedElGamal::CT sender_balance_ct;        // the current balance of pk1 (not necessarily included)
    ECPoint pk_s, pk_r;      // sender = pk1, receiver = pk2
    TwistedElGamal::MRCT transfer_ct;    // transfer = (X0 = pk_s^r, X1 = pk_r^r, X2 = pk_a^r Y = g^r h^v)
    BigInt v;                         // (defined here only for test, should be remove in the real system)  

    // valid proof
    PlaintextEquality::Proof plaintext_equality_proof;     // NIZKPoK for transfer ciphertext (X1, X2, Y)
    Bullet::Proof bullet_right_solvent_proof;      // aggregated range proof for v and m-v lie in the right range 
    TwistedElGamal::CT refresh_sender_updated_balance_ct;  // fresh encryption of updated balance (randomness is known)
    PlaintextKnowledge::Proof plaintext_knowledge_proof; // NIZKPoK for refresh ciphertext (X^*, Y^*)
    DLOGEquality::Proof dlog_equality_proof;     // fresh updated balance is correct
};

std::string GetCTxFileName(CTx &newCTx)
{
    std::string ctx_file = newCTx.pk_s.ToHexString() + "_" + newCTx.sn.ToHexString()+".ctx"; 
    return ctx_file; 
}

void PrintPP(PP &pp)
{
    PrintSplitLine('-');
    std::cout << "pp content >>>>>>" << std::endl; 
    std::cout << "RANGE_LEN = " << pp.RANGE_LEN << std::endl; 
    std::cout << "LOG_RANGE_LEN = " << pp.LOG_RANGE_LEN << std::endl; 
    std::cout << "AGG_NUM = " << pp.AGG_NUM << std::endl; // number of sub-argument (for now, we require m to be the power of 2)

    std::cout << "SN_LEN = " << pp.SN_LEN << std::endl;  
    std::cout << "DEC_THREAD_NUM = " << pp.DEC_THREAD_NUM << std::endl; 
    std::cout << "TRADEOFF_NUM = " << pp.TRADEOFF_NUM << std::endl; 

    pp.g.Print("g"); 
    pp.h.Print("h");
    pp.u.Print("u"); 
    PrintECPointVector(pp.vec_g, "vec_g"); 
    PrintECPointVector(pp.vec_h, "vec_h"); 

    pp.pk_a.Print("supervisor's pk"); 
    
    PrintSplitLine('-'); 
}

void PrintAccount(Account &Acct)
{
    std::cout << Acct.identity << " account information >>> " << std::endl;     
    Acct.pk.Print("pk"); 
    //BN_print(Acct.sk, "sk"); 
    std::cout << "encrypted balance:" << std::endl; 
    TwistedElGamal::PrintCT(Acct.balance_ct);  // current balance
    Acct.m.Print("m");  // dangerous (should only be used for speeding up the proof generation)
    Acct.sn.Print("sn"); 
    PrintSplitLine('-'); 
}

/* print the details of a confidential transaction */
void PrintCTx(CTx &newCTx)
{
    PrintSplitLine('-');
    std::string ctx_file = GetCTxFileName(newCTx);  
    std::cout << ctx_file << " content >>>>>>" << std::endl; 

    std::cout << "current sender balance >>>" << std::endl; 
    TwistedElGamal::PrintCT(newCTx.sender_balance_ct);
    std::cout << std::endl; 

    newCTx.pk_s.Print("sender's public key"); 
    newCTx.pk_r.Print("receiver's public key"); 
    std::cout << std::endl;  

    std::cout << "transfer >>>" << std::endl;
    TwistedElGamal::PrintCT(newCTx.transfer_ct);
    std::cout << std::endl; 

    std::cout << "NIZKPoK for plaintext equality >>>" << std::endl; 
    PlaintextEquality::PrintProof(newCTx.plaintext_equality_proof);
    std::cout << std::endl; 

    std::cout << "refresh updated balance >>>" << std::endl;
    TwistedElGamal::PrintCT(newCTx.refresh_sender_updated_balance_ct); 
    std::cout << std::endl;

    std::cout << "NIZKPoK for refreshing correctness >>>" << std::endl; 
    DLOGEquality::PrintProof(newCTx.dlog_equality_proof);
    std::cout << std::endl;

    std::cout << "NIZKPoK of refresh updated balance >>>" << std::endl; 
    PlaintextKnowledge::PrintProof(newCTx.plaintext_knowledge_proof); 
    std::cout << std::endl;

    std::cout << "range proofs for transfer amount and updated balance >>> " << std::endl; 
    Bullet::PrintProof(newCTx.bullet_right_solvent_proof); 
    std::cout << std::endl;

    PrintSplitLine('-'); 
}

// obtain pp for each building block
void GetBulletPPfromADCTPP(PP &pp, Bullet::PP &bullet_pp)
{
    bullet_pp.RANGE_LEN = pp.RANGE_LEN; 
    bullet_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN;
    bullet_pp.AGG_NUM = pp.AGG_NUM;  

    bullet_pp.g = pp.g; 
    bullet_pp.h = pp.h; 
    bullet_pp.u = pp.u; 
    bullet_pp.vec_g = pp.vec_g; 
    bullet_pp.vec_h = pp.vec_h; 
}

void GetEncPPfromADCTPP(PP &pp, TwistedElGamal::PP &enc_pp)
{
    enc_pp.MSG_LEN = pp.RANGE_LEN; 
    enc_pp.TRADEOFF_NUM = pp.TRADEOFF_NUM;
    enc_pp.DEC_THREAD_NUM = pp.DEC_THREAD_NUM;  
    enc_pp.MSG_SIZE = pp.MAXIMUM_COINS; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
}

// obtain pp for each building block
void GetGadgetPPfromADCTPP(PP &pp, Gadget::PP &gadget_pp)
{
    gadget_pp.RANGE_LEN = pp.RANGE_LEN; 
    gadget_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN;
    gadget_pp.AGG_NUM = pp.AGG_NUM;  

    gadget_pp.TRADEOFF_NUM = pp.TRADEOFF_NUM;
    gadget_pp.DEC_THREAD_NUM = pp.DEC_THREAD_NUM; // used by twisted ElGamal

    gadget_pp.g = pp.g; 
    gadget_pp.h = pp.h; 
    gadget_pp.u = pp.u; 
    gadget_pp.vec_g = pp.vec_g; 
    gadget_pp.vec_h = pp.vec_h; 
}

void GetPlaintextEqualityPPfromADCTPP(PP &pp, PlaintextEquality::PP &pteq_pp)
{
    pteq_pp.g = pp.g; 
    pteq_pp.h = pp.h;  
}

void GetDLOGEqualityPPfromADCTPP(PP &pp, DLOGEquality::PP &dlogeq_pp)
{
    dlogeq_pp.ss_reserve = "dummy";  
}

void GetPlaintextKnowledgePPfromADCTPP(PP &pp, PlaintextKnowledge::PP &ptknowledge_pp)
{
    ptknowledge_pp.g = pp.g; 
    ptknowledge_pp.h = pp.h; 
}

void SaveSP(SP &sp, std::string ADCT_SP_File)
{
    std::ofstream fout;
    fout.open(ADCT_SP_File, std::ios::binary); 
    fout << sp.sk_a;
    fout.close();   
}

void FetchSP(SP &sp, std::string ADCT_SP_File)
{
    std::ifstream fin; 
    fin.open(ADCT_SP_File, std::ios::binary); 
    fin >> sp.sk_a; 
    fin.close();   
}


void SavePP(PP &pp, std::string ADCT_PP_File)
{
    std::ofstream fout; 
    fout.open(ADCT_PP_File, std::ios::binary); 
    fout.write((char *)(&pp.RANGE_LEN), sizeof(pp.RANGE_LEN));
    fout.write((char *)(&pp.LOG_RANGE_LEN), sizeof(pp.LOG_RANGE_LEN));
    fout.write((char *)(&pp.AGG_NUM), sizeof(pp.AGG_NUM));
    fout.write((char *)(&pp.SN_LEN), sizeof(pp.SN_LEN));
    fout.write((char *)(&pp.DEC_THREAD_NUM), sizeof(pp.DEC_THREAD_NUM));
    fout.write((char *)(&pp.TRADEOFF_NUM), sizeof(pp.TRADEOFF_NUM));

    fout << pp.MAXIMUM_COINS;  
    fout << pp.g; 
    fout << pp.h;
    fout << pp.u; 
    SerializeECPointVector(pp.vec_g, fout); 
    SerializeECPointVector(pp.vec_h, fout); 

    fout << pp.pk_a; 
    fout << pp.sk_a;

    fout.close();   
}

void FetchPP(PP &pp, std::string ADCT_PP_File)
{
    std::ifstream fin; 
    fin.open(ADCT_PP_File, std::ios::binary); 
    fin.read((char *)(&pp.RANGE_LEN), sizeof(pp.RANGE_LEN));
    fin.read((char *)(&pp.LOG_RANGE_LEN), sizeof(pp.LOG_RANGE_LEN));
    fin.read((char *)(&pp.AGG_NUM), sizeof(pp.AGG_NUM));
    fin.read((char *)(&pp.SN_LEN), sizeof(pp.SN_LEN));
    fin.read((char *)(&pp.DEC_THREAD_NUM), sizeof(pp.DEC_THREAD_NUM));
    fin.read((char *)(&pp.TRADEOFF_NUM), sizeof(pp.TRADEOFF_NUM));

    fin >> pp.MAXIMUM_COINS;
    fin >> pp.g; 
    fin >> pp.h;
    fin >> pp.u; 

    pp.vec_g.resize(pp.RANGE_LEN * pp.AGG_NUM); 
    pp.vec_h.resize(pp.RANGE_LEN * pp.AGG_NUM); 
    DeserializeECPointVector(pp.vec_g, fin); 
    DeserializeECPointVector(pp.vec_h, fin); 

    fin >> pp.pk_a; 
    fin >> pp.sk_a; 

    fin.close();   
}

void SaveAccount(Account &user, std::string ADCT_Account_File)
{
    std::ofstream fout; 
    fout.open(ADCT_Account_File, std::ios::binary);
    fout.write((char *)(&user.identity), sizeof(user.identity));
     
    fout << user.pk;              
    fout << user.sk;             
    TwistedElGamal::SerializeCT(user.balance_ct, fout);
    fout << user.m; 
    fout << user.sn;
    fout.close();  
}

void FetchAccount(Account &user, std::string ADCT_Account_File)
{
    std::ifstream fin; 
    fin.open(ADCT_Account_File, std::ios::binary);
    fin.read((char *)(&user.identity), sizeof(user.identity));

    fin >> user.pk;              
    fin >> user.sk;             
    TwistedElGamal::DeserializeCT(user.balance_ct, fin);
    fin >> user.m; 
    fin >> user.sn;
    fin.close();  
}

// save CTx into sn.ctx file
void SaveCTx(CTx &newCTx, std::string ADCT_CTx_File)
{
    std::ofstream fout; 
    fout.open(ADCT_CTx_File, std::ios::binary); 
    
    // save sn
    fout << newCTx.sn; 
     
    // save memo info
    fout << newCTx.pk_s; 
    fout << newCTx.pk_r; 
    TwistedElGamal::SerializeCT(newCTx.transfer_ct, fout);
    
    // save proofs
    PlaintextEquality::SerializeProof(newCTx.plaintext_equality_proof, fout);
    TwistedElGamal::SerializeCT(newCTx.refresh_sender_updated_balance_ct, fout); 
    DLOGEquality::SerializeProof(newCTx.dlog_equality_proof, fout); 
    PlaintextKnowledge::SerializeProof(newCTx.plaintext_knowledge_proof, fout); 
    Bullet::SerializeProof(newCTx.bullet_right_solvent_proof, fout); 
    fout.close();

    // calculate the size of ctx_file
    std::ifstream fin; 
    fin.open(ADCT_CTx_File, std::ios::ate | std::ios::binary);
    std::cout << ADCT_CTx_File << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
}

/* recover CTx from ctx file */
void FetchCTx(CTx &newCTx, std::string ADCT_CTx_File)
{
    // Deserialize_CTx(newCTx, ctx_file); 
    std::ifstream fin; 
    fin.open(ADCT_CTx_File);

    // recover sn
    fin >> newCTx.sn;
    
    // recover memo
    fin >> newCTx.pk_s; 
    fin >> newCTx.pk_r; 
    TwistedElGamal::DeserializeCT(newCTx.transfer_ct, fin);

    // recover proof
    PlaintextEquality::DeserializeProof(newCTx.plaintext_equality_proof, fin);
    TwistedElGamal::DeserializeCT(newCTx.refresh_sender_updated_balance_ct, fin); 
    DLOGEquality::DeserializeProof(newCTx.dlog_equality_proof, fin); 
    PlaintextKnowledge::DeserializeProof(newCTx.plaintext_knowledge_proof, fin); 
    Bullet::DeserializeProof(newCTx.bullet_right_solvent_proof, fin); 
    fin.close(); 
}

/* This function implements Setup algorithm of ADCT */
void Setup(SP &sp, PP &pp, size_t RANGE_LEN, size_t AGG_NUM, size_t SN_LEN, size_t DEC_THREAD_NUM, size_t TRADEOFF_NUM)
{
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = log2(RANGE_LEN); 
    pp.AGG_NUM = AGG_NUM; 
    pp.SN_LEN = SN_LEN;
    pp.DEC_THREAD_NUM = DEC_THREAD_NUM;  
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 

    pp.g = generator; 
    pp.h = Hash::StringToECPoint(pp.g.ToByteString()); 
    pp.u = GenRandomGenerator(); // used for inside innerproduct statement
    
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, pp.RANGE_LEN)));  

    pp.vec_g = GenRandomECPointVector(RANGE_LEN*AGG_NUM); 
    pp.vec_h = GenRandomECPointVector(RANGE_LEN*AGG_NUM); 
    
    

    sp.sk_a = GenRandomBigIntLessThan(order); // sk \sample Z_p
    pp.pk_a = pp.g * sp.sk_a; // pka = g^ska  
}

/* initialize the encryption part for faster decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize ADCT >>>" << std::endl; 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp);  
    TwistedElGamal::Initialize(enc_pp); 
    PrintSplitLine('-'); 
}

/* create an account for input identity */
void CreateAccount(PP &pp, std::string identity, BigInt &init_balance, BigInt &sn, Account &newAcct)
{
    newAcct.identity = identity;
    newAcct.sn = sn;  
    TwistedElGamal::PP enc_pp;
    GetEncPPfromADCTPP(pp, enc_pp); // enc_pp.g = pp.g, enc_pp.h = pp.h;  

    TwistedElGamal::KP keypair; 
    TwistedElGamal::KeyGen(enc_pp, keypair); // generate a keypair
    newAcct.pk = keypair.pk; 
    newAcct.sk = keypair.sk;  

    newAcct.m = init_balance; 

    // initialize account balance with 0 coins
    BigInt r = Hash::StringToBigInt(newAcct.identity); 
    TwistedElGamal::Enc(enc_pp, newAcct.pk, init_balance, r, newAcct.balance_ct);

    #ifdef DEMO
        std::cout << identity << "'s ADCT account creation succeeds" << std::endl;
        newAcct.pk.Print("pk"); 
        std::cout << identity << "'s initial balance = "; 
        newAcct.m.Print(); 
        PrintSplitLine('-'); 
    #endif 
}

/* update Account if CTx is valid */
bool UpdateAccount(PP &pp, CTx &newCTx, Account &Acct_sender, Account &Acct_receiver)
{    
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 
    if ((newCTx.pk_s != Acct_sender.pk) || (newCTx.pk_r != Acct_receiver.pk)){
        std::cout << "sender and receiver addresses do not match" << std::endl;
        return false;  
    }
    else{
        Acct_sender.sn = Acct_sender.sn + bn_1;

        TwistedElGamal::CT c_out; 
        c_out.X = newCTx.transfer_ct.X[0]; c_out.Y = newCTx.transfer_ct.Y;
        TwistedElGamal::CT c_in; 
        c_in.X = newCTx.transfer_ct.X[1]; c_in.Y = newCTx.transfer_ct.Y;

        // update sender's balance
        TwistedElGamal::HomoSub(Acct_sender.balance_ct, Acct_sender.balance_ct, c_out); 
        // update receiver's balance
        TwistedElGamal::HomoAdd(Acct_receiver.balance_ct, Acct_receiver.balance_ct, c_in); 

        TwistedElGamal::Dec(enc_pp, Acct_sender.sk, Acct_sender.balance_ct, Acct_sender.m); 
        TwistedElGamal::Dec(enc_pp, Acct_receiver.sk, Acct_receiver.balance_ct, Acct_receiver.m);

        SaveAccount(Acct_sender, Acct_sender.identity+".account"); 
        SaveAccount(Acct_receiver, Acct_receiver.identity+".account"); 
        return true; 
    }
} 

/* reveal the balance */ 
void RevealBalance(PP &pp, Account &Acct, BigInt &m)
{
    TwistedElGamal::PP enc_pp;
    GetEncPPfromADCTPP(pp, enc_pp); 
    TwistedElGamal::Dec(enc_pp, Acct.sk, Acct.balance_ct, m); 
    //BN_copy(m, Acct.m); 
}

/* supervisor opens CTx */
BigInt SuperviseCTx(SP &sp, PP &pp, CTx &ctx)
{
    BigInt v; 

    std::cout << "Supervise " << GetCTxFileName(ctx) << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 
    TwistedElGamal::PP enc_pp;
    GetEncPPfromADCTPP(pp, enc_pp); 

    TwistedElGamal::CT ct; 
    ct.X = ctx.transfer_ct.X[2];
    ct.Y = ctx.transfer_ct.Y;  
    TwistedElGamal::Dec(enc_pp, sp.sk_a, ct, v); 

    std::cout << ctx.pk_s.ToHexString() << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << ctx.pk_r.ToHexString() << std::endl; 
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "supervising ctx takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return v; 
}

/* generate a confidential transaction: pk1 transfers v coins to pk2 */
void CreateCTx(PP &pp, Account &Acct_sender, BigInt &v, ECPoint &pk_r, CTx &newCTx)
{
    #ifdef DEMO
        std::cout << "begin to genetate CTx >>>>>>" << std::endl; 
    #endif
    PrintSplitLine('-'); 

    #ifdef DEMO
        std::cout <<"1. generate memo info of CTx" << std::endl;  
    #endif

    auto start_time = std::chrono::steady_clock::now(); 
    newCTx.sn = Acct_sender.sn;
    newCTx.pk_s = Acct_sender.pk; 
    newCTx.pk_r = pk_r; 

    TwistedElGamal::PP enc_pp;
    GetEncPPfromADCTPP(pp, enc_pp); 

    newCTx.v = v; 
    std::vector<ECPoint> vec_pk = {newCTx.pk_s, newCTx.pk_r, pp.pk_a}; 
    BigInt r = GenRandomBigIntLessThan(order);
    TwistedElGamal::Enc(enc_pp, vec_pk, newCTx.v, r, newCTx.transfer_ct); 

    newCTx.sender_balance_ct.X = Acct_sender.balance_ct.X;
    newCTx.sender_balance_ct.Y = Acct_sender.balance_ct.Y;

    #ifdef DEMO
        std::cout << "2. generate NIZKPoK for plaintext equality" << std::endl;  
    #endif
    // begin to generate the valid proof for ctx
    std::string transcript_str = newCTx.sn.ToHexString(); 

    // generate NIZK proof for validity of transfer              
    PlaintextEquality::PP pteq_pp; 
    GetPlaintextEqualityPPfromADCTPP(pp, pteq_pp);
    
    PlaintextEquality::Instance pteq_instance;
     
    pteq_instance.pk1 = newCTx.pk_s; 
    pteq_instance.pk2 = newCTx.pk_r; 
    pteq_instance.pk3 = pp.pk_a; 
    pteq_instance.X1 = newCTx.transfer_ct.X[0];
    pteq_instance.X2 = newCTx.transfer_ct.X[1];
    pteq_instance.X3 = newCTx.transfer_ct.X[2];
    pteq_instance.Y = newCTx.transfer_ct.Y;
    
    PlaintextEquality::Witness pteq_witness; 
    pteq_witness.r = r; 
    pteq_witness.v = v; 

    PlaintextEquality::Prove(pteq_pp, pteq_instance, pteq_witness, transcript_str, newCTx.plaintext_equality_proof);


    #ifdef DEMO
        std::cout << "3. compute updated balance" << std::endl;  
    #endif
    // compute the updated balance

    TwistedElGamal::CT sender_updated_balance_ct; 
    sender_updated_balance_ct.X = newCTx.sender_balance_ct.X - newCTx.transfer_ct.X[0];
    sender_updated_balance_ct.Y = newCTx.sender_balance_ct.Y - newCTx.transfer_ct.Y;     

    #ifdef DEMO
        std::cout << "4. compute refreshed updated balance" << std::endl;  
    #endif
    // refresh the updated balance (with random coins r^*)
    BigInt r_star = GenRandomBigIntLessThan(order);    
    TwistedElGamal::ReEnc(enc_pp, Acct_sender.pk, Acct_sender.sk, 
                          sender_updated_balance_ct, r_star, newCTx.refresh_sender_updated_balance_ct);

    #ifdef DEMO
        std::cout << "5. generate NIZKPoK for correct refreshing and authenticate the memo info" << std::endl;  
    #endif
    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOGEquality::PP dlogeq_pp; 
    GetDLOGEqualityPPfromADCTPP(pp, dlogeq_pp); 
    
    DLOGEquality::Instance dlogeq_instance; 
       
    dlogeq_instance.g1 = sender_updated_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; // g1 = Y-Y^* = g^{r-r^*} 
    dlogeq_instance.h1 = sender_updated_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; // h1 = X-X^* = pk^{r-r^*}
    
    dlogeq_instance.g2 = enc_pp.g;                         // g2 = g
    dlogeq_instance.h2 = Acct_sender.pk;                    // h2 = pk  
    DLOGEquality::Witness dlogeq_witness;  
    dlogeq_witness.w = Acct_sender.sk; 

    DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, newCTx.dlog_equality_proof); 


    #ifdef DEMO
        std::cout << "6. generate NIZKPoK for refreshed updated balance" << std::endl;  
    #endif
    PlaintextKnowledge::PP ptke_pp;
    GetPlaintextKnowledgePPfromADCTPP(pp, ptke_pp);

    PlaintextKnowledge::Instance ptke_instance; 

    ptke_instance.pk = Acct_sender.pk; 
    ptke_instance.X = newCTx.refresh_sender_updated_balance_ct.X; 
    ptke_instance.Y = newCTx.refresh_sender_updated_balance_ct.Y; 
    
    PlaintextKnowledge::Witness ptke_witness; 
    ptke_witness.r = r_star; 
    ptke_witness.v = Acct_sender.m - v; 

    PlaintextKnowledge::Prove(ptke_pp, ptke_instance, ptke_witness, 
                              transcript_str, newCTx.plaintext_knowledge_proof); 

    #ifdef DEMO
        std::cout << "7. generate range proofs for transfer amount and updated balance" << std::endl;    
    #endif
    
    // aggregated range proof for v and m-v lie in the right range 
    Bullet::PP bullet_pp; 
    GetBulletPPfromADCTPP(pp, bullet_pp);

    Bullet::Instance bullet_instance;
    bullet_instance.C = {newCTx.transfer_ct.Y, newCTx.refresh_sender_updated_balance_ct.Y};

    Bullet::Witness bullet_witness;  
    bullet_witness.r = {pteq_witness.r, ptke_witness.r}; 
    bullet_witness.v = {pteq_witness.v, ptke_witness.v};

    Bullet::Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, newCTx.bullet_right_solvent_proof); 


    #ifdef DEMO
        PrintSplitLine('-'); 
    #endif

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "ctx generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

/* check if the given confidential transaction is valid */ 
bool VerifyCTx(PP &pp, CTx &newCTx)
{     
    #ifdef DEMO
        std::cout << "begin to verify CTx >>>>>>" << std::endl; 
    #endif

    auto start_time = std::chrono::steady_clock::now(); 
    
    bool Validity; 
    bool V1, V2, V3, V4; 

    std::string transcript_str = newCTx.sn.ToHexString(); 

    PlaintextEquality::PP pteq_pp;
    GetPlaintextEqualityPPfromADCTPP(pp, pteq_pp); 

    PlaintextEquality::Instance pteq_instance; 
    pteq_instance.pk1 = newCTx.pk_s;
    pteq_instance.pk2 = newCTx.pk_r;
    pteq_instance.pk3 = pp.pk_a;
    pteq_instance.X1 = newCTx.transfer_ct.X[0];
    pteq_instance.X2 = newCTx.transfer_ct.X[1];
    pteq_instance.X3 = newCTx.transfer_ct.X[2];
    pteq_instance.Y = newCTx.transfer_ct.Y;

    V1 = PlaintextEquality::Verify(pteq_pp, pteq_instance, transcript_str, newCTx.plaintext_equality_proof);
    

    #ifdef DEMO
        if (V1) std::cout << "NIZKPoK for plaintext equality accepts" << std::endl; 
        else std::cout << "NIZKPoK for plaintext equality rejects" << std::endl; 
    #endif

    // check V2
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 

    TwistedElGamal::CT updated_sender_balance_ct; 
    updated_sender_balance_ct.X = newCTx.sender_balance_ct.X - newCTx.transfer_ct.X[0]; 
    updated_sender_balance_ct.Y = newCTx.sender_balance_ct.Y - newCTx.transfer_ct.Y; 

    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOGEquality::PP dlogeq_pp; 
    GetDLOGEqualityPPfromADCTPP(pp, dlogeq_pp);

    DLOGEquality::Instance dlogeq_instance; 

    dlogeq_instance.g1 = updated_sender_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; 
    dlogeq_instance.h1 = updated_sender_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; 
    dlogeq_instance.g2 = enc_pp.g; 
    dlogeq_instance.h2 = newCTx.pk_s;  

    V2 = DLOGEquality::Verify(dlogeq_pp, dlogeq_instance, transcript_str, newCTx.dlog_equality_proof); 

    #ifdef DEMO
        if (V2) std::cout << "NIZKPoK for refreshing correctness accepts and memo info is authenticated" << std::endl; 
        else std::cout << "NIZKPoK for refreshing correctness rejects or memo info is unauthenticated" << std::endl; 
    #endif

    PlaintextKnowledge::PP ptke_pp; 
    GetPlaintextKnowledgePPfromADCTPP(pp, ptke_pp);

    PlaintextKnowledge::Instance ptke_instance; 
    ptke_instance.pk = newCTx.pk_s; 
    ptke_instance.X = newCTx.refresh_sender_updated_balance_ct.X; 
    ptke_instance.Y = newCTx.refresh_sender_updated_balance_ct.Y; 

    V3 = PlaintextKnowledge::Verify(ptke_pp, ptke_instance, transcript_str, newCTx.plaintext_knowledge_proof);

    #ifdef DEMO
        if (V3) std::cout << "NIZKPoK for refresh updated balance accepts" << std::endl; 
        else std::cout << "NIZKPoK for refresh updated balance rejects" << std::endl; 
    #endif

    // aggregated range proof for v and m-v lie in the right range 
    Bullet::PP bullet_pp; 
    GetBulletPPfromADCTPP(pp, bullet_pp);

    Bullet::Instance bullet_instance;
    bullet_instance.C = {newCTx.transfer_ct.Y, newCTx.refresh_sender_updated_balance_ct.Y};

    V4 = Bullet::Verify(bullet_pp, bullet_instance, transcript_str, newCTx.bullet_right_solvent_proof); 

    #ifdef DEMO
        if (V4) std::cout << "range proofs for transfer amount and updated balance accept" << std::endl; 
        else std::cout << "range proofs for transfer amount and updated balance reject" << std::endl;   
    #endif

    Validity = V1 && V2 && V3 && V4; 

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
bool Miner(PP &pp, CTx &newCTx, Account &Acct_sender, Account &Acct_receiver)
{
    if (newCTx.pk_s != Acct_sender.pk){
        std::cout << "sender does not match CTx" << std::endl; 
        return false; 
    }

    if (newCTx.pk_r != Acct_receiver.pk){
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
bool JustifyPolicy(PP &pp, Account &Acct_user, CTx &doubtCTx, 
                   OpenPolicy &policy, DLOGEquality::Proof &open_proof)
{
    if ((Acct_user.pk != doubtCTx.pk_s) && (Acct_user.pk != doubtCTx.pk_r)) {
        std::cout << "the identity of claimer does not match ctx" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    DLOGEquality::PP dlogeq_pp;
    GetDLOGEqualityPPfromADCTPP(pp, dlogeq_pp); 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 

    DLOGEquality::Instance dlogeq_instance;  
    
    dlogeq_instance.g1 = doubtCTx.transfer_ct.Y - enc_pp.h * policy.v; // g1 = g^r h^v - h^v = g^r
    dlogeq_instance.g2 = enc_pp.g; 
    if (Acct_user.pk == doubtCTx.pk_s){
        dlogeq_instance.h1 = doubtCTx.transfer_ct.X[0]; // pk1^r
        dlogeq_instance.h2 = doubtCTx.pk_s;  
    }
    else{
        dlogeq_instance.h1 = doubtCTx.transfer_ct.X[1];  // pk2^r
        dlogeq_instance.h2 = doubtCTx.pk_r;  
    }
    DLOGEquality::Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_user.sk; 

    std::string transcript_str = ""; 
    DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, open_proof); 
    
    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for open policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return true; 
} 

/* check if the proposed NIZK proof PI for open policy is valid */ 
bool AuditPolicy(PP &pp, Account &Acct_user, CTx &doubtCTx,  
                 OpenPolicy &policy, DLOGEquality::Proof &open_proof)
{ 
    if ((Acct_user.pk != doubtCTx.pk_s) && (Acct_user.pk != doubtCTx.pk_r)){
        std::cout << "the identity of claimer does not match ctx" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    DLOGEquality::PP dlogeq_pp; 
    GetDLOGEqualityPPfromADCTPP(pp, dlogeq_pp); 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 

    DLOGEquality::Instance dlogeq_instance; 
    dlogeq_instance.g1 = doubtCTx.transfer_ct.Y - enc_pp.h * policy.v;  // g1 = g^r h^v - h^v = g^r
    dlogeq_instance.g2 = enc_pp.g;
    if (Acct_user.pk == doubtCTx.pk_s){
        dlogeq_instance.h1 = doubtCTx.transfer_ct.X[0];
        dlogeq_instance.h2 = doubtCTx.pk_s;  
    }
    else{
        dlogeq_instance.h1 = doubtCTx.transfer_ct.X[1];
        dlogeq_instance.h2 = doubtCTx.pk_r;  
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
bool JustifyPolicy(PP &pp, Account &Acct_user, CTx &ctx1, CTx &ctx2,  
                   RatePolicy &policy, DLOGEquality::Proof &rate_proof)
{
    if (Acct_user.pk != ctx1.pk_r || Acct_user.pk != ctx2.pk_s){
        std::cout << "the identity of claimer does not match" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    
    DLOGEquality::PP dlogeq_pp;
    GetDLOGEqualityPPfromADCTPP(pp, dlogeq_pp); 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 

    DLOGEquality::Instance dlogeq_instance; 
    dlogeq_instance.g1 = enc_pp.g;     // g1 = g 
    dlogeq_instance.h1 = Acct_user.pk; // g2 = pk = g^sk

    TwistedElGamal::CT ct_in; 
    ct_in.X = ctx1.transfer_ct.X[1]; 
    ct_in.Y = ctx1.transfer_ct.Y; 
    TwistedElGamal::ScalarMul(ct_in, ct_in, policy.t1); 
    
    TwistedElGamal::CT ct_out; 
    ct_out.X = ctx2.transfer_ct.X[0]; 
    ct_out.Y = ctx2.transfer_ct.Y; 
    TwistedElGamal::ScalarMul(ct_out, ct_out, policy.t2); 

    TwistedElGamal::CT ct_diff;  
    TwistedElGamal::HomoSub(ct_diff, ct_in, ct_out);  

    dlogeq_instance.g2 = ct_diff.Y; 
    dlogeq_instance.h2 = ct_diff.X; 

    DLOGEquality::Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_user.sk; 

    std::string transcript_str = ""; 
    DLOGEquality::Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, rate_proof); 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for rate policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return true; 
} 

/* check if the NIZK proof PI for rate policy is valid */
bool AuditPolicy(PP &pp, ECPoint pk, CTx &ctx1, CTx &ctx2,  
                 RatePolicy &policy, DLOGEquality::Proof &rate_proof)
{ 
    if ((pk != ctx1.pk_r) || (pk != ctx2.pk_s)){
        std::cout << "the identity of claimer does not match" << std::endl; 
        return false; 
    }
    
    auto start_time = std::chrono::steady_clock::now(); 
    
    DLOGEquality::PP dlogeq_pp; 
    GetDLOGEqualityPPfromADCTPP(pp, dlogeq_pp); 
    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 

    DLOGEquality::Instance dlogeq_instance; 
    dlogeq_instance.g1 = enc_pp.g;     // g1 = g 
    dlogeq_instance.h1 = pk; // g2 = pk = g^sk

    TwistedElGamal::CT ct_in; 
    ct_in.X = ctx1.transfer_ct.X[1]; 
    ct_in.Y = ctx1.transfer_ct.Y; 
    TwistedElGamal::ScalarMul(ct_in, ct_in, policy.t1); 
    
    TwistedElGamal::CT ct_out; 
    ct_out.X = ctx2.transfer_ct.X[0]; 
    ct_out.Y = ctx2.transfer_ct.Y; 
    TwistedElGamal::ScalarMul(ct_out, ct_out, policy.t2);  

    TwistedElGamal::CT ct_diff;  
    TwistedElGamal::HomoSub(ct_diff, ct_in, ct_out);  

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
bool JustifyPolicy(PP &pp, Account &Acct_user, std::vector<CTx> &ctx_set, 
                   LimitPolicy &policy, Gadget::Proof_type2 &limit_proof)
{
    for(auto i = 0; i < ctx_set.size(); i++){
        if (Acct_user.pk != ctx_set[i].pk_s){
            std::cout << "the identity of claimer does not match" << std::endl; 
            return false; 
        }
    }

    auto start_time = std::chrono::steady_clock::now(); 

    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 
    TwistedElGamal::CT ct_sum;
    ct_sum.X.SetInfinity();
    ct_sum.Y.SetInfinity(); 
    TwistedElGamal::CT ct_temp; 
    for(auto i = 0; i < ctx_set.size(); i++)
    {
        ct_temp.X = ctx_set[i].transfer_ct.X[0]; 
        ct_temp.Y = ctx_set[i].transfer_ct.Y;
        TwistedElGamal::HomoAdd(ct_sum, ct_sum, ct_temp); 
    } 
 
    Gadget::PP gadget_pp;
    GetGadgetPPfromADCTPP(pp, gadget_pp); 
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
bool AuditPolicy(PP &pp, ECPoint pk, std::vector<CTx> &ctx_set, 
                 LimitPolicy &policy, Gadget::Proof_type2 &limit_proof)
{ 
    for(auto i = 0; i < ctx_set.size(); i++){
        if (pk != ctx_set[i].pk_s){
            std::cout << "the identity of claimer does not match" << std::endl; 
            return false; 
        }
    }

    auto start_time = std::chrono::steady_clock::now(); 

    TwistedElGamal::PP enc_pp; 
    GetEncPPfromADCTPP(pp, enc_pp); 
    TwistedElGamal::CT ct_sum;
    ct_sum.X.SetInfinity();
    ct_sum.Y.SetInfinity(); 
    TwistedElGamal::CT ct_temp; 
    for(auto i = 0; i < ctx_set.size(); i++)
    {
        ct_temp.X = ctx_set[i].transfer_ct.X[0]; 
        ct_temp.Y = ctx_set[i].transfer_ct.Y;
        TwistedElGamal::HomoAdd(ct_sum, ct_sum, ct_temp); 
    } 
 
    Gadget::PP gadget_pp;
    GetGadgetPPfromADCTPP(pp, gadget_pp); 
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

}

#endif