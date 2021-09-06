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

// define the structure of system parameters
struct ADCT_PP{
    size_t RANGE_LEN; // the maximum coin value is 2^RANGE_LEN 
    size_t LOG_RANGE_LEN; // this parameter will be used by Bulletproof
    size_t AGG_NUM;    // number of aggregated proofs (for now, we require m to be the power of 2)
    size_t SN_LEN;    // sn length
    size_t TRADEOFF_NUM; // used for fast decryption 
    size_t THREAD_NUM; // used by twisted ElGamal 

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
struct ADCT_SP{
    BigInt sk_a;   // supervisor's sk
};

struct ADCT_Account{
    std::string identity;     // id
    ECPoint pk;              // public key
    BigInt sk;              // secret key
    Twisted_ElGamal_CT balance_ct;  // current balance
    BigInt m;               // dangerous (should only be used for speeding up the proof generation)
    BigInt sn; 
};

// define the structure for confidential transaction
struct ADCT_CTx{
    BigInt sn;                        // serial number: uniquely defines a transaction
    // memo information
    Twisted_ElGamal_CT sender_balance_ct;        // the current balance of pk1 (not necessarily included)
    ECPoint pk_s, pk_r;      // sender = pk1, receiver = pk2
    MR_Twisted_ElGamal_CT transfer_ct;    // transfer = (X0 = pk_s^r, X1 = pk_r^r, X2 = pk_a^r Y = g^r h^v)
    BigInt v;                         // (defined here only for test, should be remove in the real system)  

    // valid proof
    Plaintext_Equality_Proof plaintext_equality_proof;     // NIZKPoK for transfer ciphertext (X1, X2, Y)
    Bullet_Proof bullet_right_solvent_proof;      // aggregated range proof for v and m-v lie in the right range 
    Twisted_ElGamal_CT refresh_sender_updated_balance_ct;  // fresh encryption of updated balance (randomness is known)
    Plaintext_Knowledge_Proof plaintext_knowledge_proof; // NIZKPoK for refresh ciphertext (X^*, Y^*)
    DLOG_Equality_Proof dlog_equality_proof;     // fresh updated balance is correct
};

std::string GetCTxFileName(ADCT_CTx &newCTx)
{
    std::string ctx_file = ECPointToHexString(newCTx.pk_s) + "_" + BigIntToHexString(newCTx.sn)+".ctx"; 
    return ctx_file; 
}

void ADCT_Print_PP(ADCT_PP &pp)
{
    Print_SplitLine('-');
    std::cout << "pp content >>>>>>" << std::endl; 
    std::cout << "RANGE_LEN = " << pp.RANGE_LEN << std::endl; 
    std::cout << "LOG_RANGE_LEN = " << pp.LOG_RANGE_LEN << std::endl; 
    std::cout << "AGG_NUM = " << pp.AGG_NUM << std::endl; // number of sub-argument (for now, we require m to be the power of 2)

    std::cout << "SN_LEN = " << pp.SN_LEN << std::endl;  
    std::cout << "THREAD_NUM = " << pp.THREAD_NUM << std::endl; 
    std::cout << "TRADEOFF_NUM = " << pp.TRADEOFF_NUM << std::endl; 

    pp.g.Print("g"); 
    pp.h.Print("h");
    pp.u.Print("u"); 
    Print_ECPointVector(pp.vec_g, "vec_g"); 
    Print_ECPointVector(pp.vec_h, "vec_h"); 

    pp.pk_a.Print("supervisor's pk"); 
    
    Print_SplitLine('-'); 
}

void ADCT_Print_Account(ADCT_Account &Acct)
{
    std::cout << Acct.identity << " account information >>> " << std::endl;     
    Acct.pk.Print("pk"); 
    //BN_print(Acct.sk, "sk"); 
    std::cout << "encrypted balance:" << std::endl; 
    Twisted_ElGamal_Print_CT(Acct.balance_ct);  // current balance
    Acct.m.Print("m");  // dangerous (should only be used for speeding up the proof generation)
    Acct.sn.Print("sn"); 
    Print_SplitLine('-'); 
}

/* print the details of a confidential transaction */
void ADCT_Print_CTx(ADCT_CTx &newCTx)
{
    Print_SplitLine('-');
    std::string ctx_file = GetCTxFileName(newCTx);  
    std::cout << ctx_file << " content >>>>>>" << std::endl; 

    std::cout << "current sender balance >>>" << std::endl; 
    Twisted_ElGamal_Print_CT(newCTx.sender_balance_ct);
    std::cout << std::endl; 

    newCTx.pk_s.Print("sender's public key"); 
    newCTx.pk_r.Print("receiver's public key"); 
    std::cout << std::endl;  

    std::cout << "transfer >>>" << std::endl;
    MR_Twisted_ElGamal_Print_CT(newCTx.transfer_ct);
    std::cout << std::endl; 

    std::cout << "NIZKPoK for plaintext equality >>>" << std::endl; 
    Plaintext_Equality_Print_Proof(newCTx.plaintext_equality_proof);
    std::cout << std::endl; 

    std::cout << "refresh updated balance >>>" << std::endl;
    Twisted_ElGamal_Print_CT(newCTx.refresh_sender_updated_balance_ct); 
    std::cout << std::endl;

    std::cout << "NIZKPoK for refreshing correctness >>>" << std::endl; 
    DLOG_Equality_Print_Proof(newCTx.dlog_equality_proof);
    std::cout << std::endl;

    std::cout << "NIZKPoK of refresh updated balance >>>" << std::endl; 
    Plaintext_Knowledge_Print_Proof(newCTx.plaintext_knowledge_proof); 
    std::cout << std::endl;

    std::cout << "range proofs for transfer amount and updated balance >>> " << std::endl; 
    Bullet_Print_Proof(newCTx.bullet_right_solvent_proof); 
    std::cout << std::endl;

    Print_SplitLine('-'); 
}

// obtain pp for each building block
void Get_Bullet_PP_from_ADCT_PP(ADCT_PP &pp, Bullet_PP &bullet_pp)
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

void Get_Enc_PP_from_ADCT_PP(ADCT_PP &pp, Twisted_ElGamal_PP &enc_pp)
{
    enc_pp.MSG_LEN = pp.RANGE_LEN; 
    enc_pp.TRADEOFF_NUM = pp.TRADEOFF_NUM;
    enc_pp.THREAD_NUM = pp.THREAD_NUM;  
    enc_pp.MSG_SIZE = pp.MAXIMUM_COINS; 
    enc_pp.g = pp.g; 
    enc_pp.h = pp.h;  
}

// obtain pp for each building block
void Get_Gadget_PP_from_ADCT_PP(ADCT_PP &pp, Gadget_PP &gadget_pp)
{
    gadget_pp.RANGE_LEN = pp.RANGE_LEN; 
    gadget_pp.LOG_RANGE_LEN = pp.LOG_RANGE_LEN;
    gadget_pp.AGG_NUM = pp.AGG_NUM;  

    gadget_pp.TRADEOFF_NUM = pp.TRADEOFF_NUM;
    gadget_pp.THREAD_NUM = pp.THREAD_NUM; // used by twisted ElGamal

    gadget_pp.g = pp.g; 
    gadget_pp.h = pp.h; 
    gadget_pp.u = pp.u; 
    gadget_pp.vec_g = pp.vec_g; 
    gadget_pp.vec_h = pp.vec_h; 
}

void Get_Plaintext_Equality_PP_from_ADCT_PP(ADCT_PP &pp, Plaintext_Equality_PP &pteq_pp)
{
    pteq_pp.g = pp.g; 
    pteq_pp.h = pp.h;  
}

void Get_DLOG_Equality_PP_from_ADCT_PP(ADCT_PP &pp, DLOG_Equality_PP &dlogeq_pp)
{
    dlogeq_pp.ss_reserve = "dummy";  
}

void Get_Plaintext_Knowledge_PP_from_ADCT_PP(ADCT_PP &pp, Plaintext_Knowledge_PP &ptknowledge_pp)
{
    ptknowledge_pp.g = pp.g; 
    ptknowledge_pp.h = pp.h; 
}

void ADCT_Save_SP(ADCT_SP &sp, std::string ADCT_SP_File)
{
    std::ofstream fout;
    fout.open(ADCT_SP_File, std::ios::binary); 
    fout << sp.sk_a;
    fout.close();   
}

void ADCT_Fetch_SP(ADCT_SP &sp, std::string ADCT_SP_File)
{
    std::ifstream fin; 
    fin.open(ADCT_SP_File, std::ios::binary); 
    fin >> sp.sk_a; 
    fin.close();   
}


void ADCT_Save_PP(ADCT_PP &pp, std::string ADCT_PP_File)
{
    std::ofstream fout; 
    fout.open(ADCT_PP_File, std::ios::binary); 
    fout.write((char *)(&pp.RANGE_LEN), sizeof(pp.RANGE_LEN));
    fout.write((char *)(&pp.LOG_RANGE_LEN), sizeof(pp.LOG_RANGE_LEN));
    fout.write((char *)(&pp.AGG_NUM), sizeof(pp.AGG_NUM));
    fout.write((char *)(&pp.SN_LEN), sizeof(pp.SN_LEN));
    fout.write((char *)(&pp.THREAD_NUM), sizeof(pp.THREAD_NUM));
    fout.write((char *)(&pp.TRADEOFF_NUM), sizeof(pp.TRADEOFF_NUM));

    fout << pp.MAXIMUM_COINS;  
    fout << pp.g; 
    fout << pp.h;
    fout << pp.u; 
    Serialize_ECPointVector(pp.vec_g, fout); 
    Serialize_ECPointVector(pp.vec_h, fout); 

    fout << pp.pk_a; 
    fout << pp.sk_a;

    fout.close();   
}

void ADCT_Fetch_PP(ADCT_PP &pp, std::string ADCT_PP_File)
{
    std::ifstream fin; 
    fin.open(ADCT_PP_File, std::ios::binary); 
    fin.read((char *)(&pp.RANGE_LEN), sizeof(pp.RANGE_LEN));
    fin.read((char *)(&pp.LOG_RANGE_LEN), sizeof(pp.LOG_RANGE_LEN));
    fin.read((char *)(&pp.AGG_NUM), sizeof(pp.AGG_NUM));
    fin.read((char *)(&pp.SN_LEN), sizeof(pp.SN_LEN));
    fin.read((char *)(&pp.THREAD_NUM), sizeof(pp.THREAD_NUM));
    fin.read((char *)(&pp.TRADEOFF_NUM), sizeof(pp.TRADEOFF_NUM));

    fin >> pp.MAXIMUM_COINS;
    fin >> pp.g; 
    fin >> pp.h;
    fin >> pp.u; 

    pp.vec_g.resize(pp.RANGE_LEN * pp.AGG_NUM); 
    pp.vec_h.resize(pp.RANGE_LEN * pp.AGG_NUM); 
    Deserialize_ECPointVector(pp.vec_g, fin); 
    Deserialize_ECPointVector(pp.vec_h, fin); 

    fin >> pp.pk_a; 
    fin >> pp.sk_a; 

    fin.close();   
}

void ADCT_Save_Account(ADCT_Account &user, std::string ADCT_Account_File)
{
    std::ofstream fout; 
    fout.open(ADCT_Account_File, std::ios::binary);
    fout.write((char *)(&user.identity), sizeof(user.identity));
     
    fout << user.pk;              
    fout << user.sk;             
    Twisted_ElGamal_Serialize_CT(user.balance_ct, fout);
    fout << user.m; 
    fout << user.sn;
    fout.close();  
}

void ADCT_Fetch_Account(ADCT_Account &user, std::string ADCT_Account_File)
{
    std::ifstream fin; 
    fin.open(ADCT_Account_File, std::ios::binary);
    fin.read((char *)(&user.identity), sizeof(user.identity));

    fin >> user.pk;              
    fin >> user.sk;             
    Twisted_ElGamal_Deserialize_CT(user.balance_ct, fin);
    fin >> user.m; 
    fin >> user.sn;
    fin.close();  
}

// save CTx into sn.ctx file
void ADCT_Save_CTx(ADCT_CTx &newCTx, std::string ADCT_CTx_File)
{
    std::ofstream fout; 
    fout.open(ADCT_CTx_File, std::ios::binary); 
    
    // save sn
    fout << newCTx.sn; 
     
    // save memo info
    fout << newCTx.pk_s; 
    fout << newCTx.pk_r; 
    MR_Twisted_ElGamal_Serialize_CT(newCTx.transfer_ct, fout);
    
    // save proofs
    Plaintext_Equality_Serialize_Proof(newCTx.plaintext_equality_proof, fout);
    Twisted_ElGamal_Serialize_CT(newCTx.refresh_sender_updated_balance_ct, fout); 
    DLOG_Equality_Serialize_Proof(newCTx.dlog_equality_proof, fout); 
    Plaintext_Knowledge_Serialize_Proof(newCTx.plaintext_knowledge_proof, fout); 
    Bullet_Serialize_Proof(newCTx.bullet_right_solvent_proof, fout); 
    fout.close();

    // calculate the size of ctx_file
    std::ifstream fin; 
    fin.open(ADCT_CTx_File, std::ios::ate | std::ios::binary);
    std::cout << ADCT_CTx_File << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
}

/* recover CTx from ctx file */
void ADCT_Fetch_CTx(ADCT_CTx &newCTx, std::string ADCT_CTx_File)
{
    // Deserialize_CTx(newCTx, ctx_file); 
    std::ifstream fin; 
    fin.open(ADCT_CTx_File);

    // recover sn
    fin >> newCTx.sn;
    
    // recover memo
    fin >> newCTx.pk_s; 
    fin >> newCTx.pk_r; 
    MR_Twisted_ElGamal_Deserialize_CT(newCTx.transfer_ct, fin);

    // recover proof
    Plaintext_Equality_Deserialize_Proof(newCTx.plaintext_equality_proof, fin);
    Twisted_ElGamal_Deserialize_CT(newCTx.refresh_sender_updated_balance_ct, fin); 
    DLOG_Equality_Deserialize_Proof(newCTx.dlog_equality_proof, fin); 
    Plaintext_Knowledge_Deserialize_Proof(newCTx.plaintext_knowledge_proof, fin); 
    Bullet_Deserialize_Proof(newCTx.bullet_right_solvent_proof, fin); 
    fin.close(); 
}

/* This function implements Setup algorithm of ADCT */
void ADCT_Setup(ADCT_SP &sp, ADCT_PP &pp, size_t RANGE_LEN, size_t AGG_NUM, 
                size_t SN_LEN, size_t THREAD_NUM, size_t TRADEOFF_NUM)
{
    pp.RANGE_LEN = RANGE_LEN; 
    pp.LOG_RANGE_LEN = log2(RANGE_LEN); 
    pp.AGG_NUM = AGG_NUM; 
    pp.SN_LEN = SN_LEN;
    pp.THREAD_NUM = THREAD_NUM;  
    pp.TRADEOFF_NUM = TRADEOFF_NUM; 

    pp.g = generator; 
    pp.h = HashToPoint(ECPointToByteString(pp.g));
    pp.u = GenRandomGenerator(); // used for inside innerproduct statement
    
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, pp.RANGE_LEN)));  

    pp.vec_g.resize(RANGE_LEN*AGG_NUM);
    pp.vec_h.resize(RANGE_LEN*AGG_NUM); 
    GenRandomECPointVector(pp.vec_g); 
    GenRandomECPointVector(pp.vec_h);

    sp.sk_a = GenRandomBigIntLessThan(order); // sk \sample Z_p
    pp.pk_a = pp.g * sp.sk_a; // pka = g^ska  
}

/* initialize the encryption part for faster decryption */
void ADCT_Initialize(ADCT_PP &pp)
{
    std::cout << "initialize ADCT >>>" << std::endl; 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp);  
    Twisted_ElGamal_Initialize(enc_pp); 
    Print_SplitLine('-'); 
}

/* create an account for input identity */
void ADCT_Create_Account(ADCT_PP &pp, std::string identity, BigInt &init_balance, BigInt &sn, ADCT_Account &newAcct)
{
    newAcct.identity = identity;
    newAcct.sn = sn;  
    Twisted_ElGamal_PP enc_pp;
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); // enc_pp.g = pp.g, enc_pp.h = pp.h;  

    Twisted_ElGamal_KP keypair; 
    Twisted_ElGamal_KeyGen(enc_pp, keypair); // generate a keypair
    newAcct.pk = keypair.pk; 
    newAcct.sk = keypair.sk;  

    newAcct.m = init_balance; 

    // initialize account balance with 0 coins
    BigInt r = HashToBigInt(newAcct.identity); 
    Twisted_ElGamal_Enc(enc_pp, newAcct.pk, init_balance, r, newAcct.balance_ct);

    #ifdef DEMO
        std::cout << identity << "'s ADCT account creation succeeds" << std::endl;
        newAcct.pk.Print("pk"); 
        std::cout << identity << "'s initial balance = "; 
        newAcct.m.Print(); 
        Print_SplitLine('-'); 
    #endif 
}

/* update Account if CTx is valid */
bool ADCT_Update_Account(ADCT_PP &pp, ADCT_CTx &newCTx, ADCT_Account &Acct_sender, ADCT_Account &Acct_receiver)
{    
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 
    if ((newCTx.pk_s != Acct_sender.pk) || (newCTx.pk_r != Acct_receiver.pk)){
        std::cout << "sender and receiver addresses do not match" << std::endl;
        return false;  
    }
    else{
        Acct_sender.sn = Acct_sender.sn + bn_1;

        Twisted_ElGamal_CT c_out; 
        c_out.X = newCTx.transfer_ct.X[0]; c_out.Y = newCTx.transfer_ct.Y;
        Twisted_ElGamal_CT c_in; 
        c_in.X = newCTx.transfer_ct.X[1]; c_in.Y = newCTx.transfer_ct.Y;

        // update sender's balance
        Twisted_ElGamal_HomoSub(Acct_sender.balance_ct, Acct_sender.balance_ct, c_out); 
        // update receiver's balance
        Twisted_ElGamal_HomoAdd(Acct_receiver.balance_ct, Acct_receiver.balance_ct, c_in); 

        Twisted_ElGamal_Dec(enc_pp, Acct_sender.sk, Acct_sender.balance_ct, Acct_sender.m); 
        Twisted_ElGamal_Dec(enc_pp, Acct_receiver.sk, Acct_receiver.balance_ct, Acct_receiver.m);

        ADCT_Save_Account(Acct_sender, Acct_sender.identity+".account"); 
        ADCT_Save_Account(Acct_receiver, Acct_receiver.identity+".account"); 
        return true; 
    }
} 

/* reveal the balance */ 
void ADCT_Reveal_Balance(ADCT_PP &pp, ADCT_Account &Acct, BigInt &m)
{
    Twisted_ElGamal_PP enc_pp;
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 
    Twisted_ElGamal_Dec(enc_pp, Acct.sk, Acct.balance_ct, m); 
    //BN_copy(m, Acct.m); 
}

/* supervisor opens CTx */
BigInt ADCT_Supervise_CTx(ADCT_SP &sp, ADCT_PP &pp, ADCT_CTx &ctx)
{
    BigInt v; 

    std::cout << "Supervise " << GetCTxFileName(ctx) << std::endl; 
    auto start_time = std::chrono::steady_clock::now(); 
    Twisted_ElGamal_PP enc_pp;
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    Twisted_ElGamal_CT ct; 
    ct.X = ctx.transfer_ct.X[2];
    ct.Y = ctx.transfer_ct.Y;  
    Twisted_ElGamal_Dec(enc_pp, sp.sk_a, ct, v); 

    std::cout << ECPointToHexString(ctx.pk_s) << " transfers " << BN_bn2dec(v.bn_ptr) 
    << " coins to " << ECPointToHexString(ctx.pk_r) << std::endl; 
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "supervising ctx takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return v; 
}

/* generate a confidential transaction: pk1 transfers v coins to pk2 */
void ADCT_Create_CTx(ADCT_PP &pp, ADCT_Account &Acct_sender, BigInt &v, ECPoint &pk_r, ADCT_CTx &newCTx)
{
    #ifdef DEMO
    std::cout << "begin to genetate CTx >>>>>>" << std::endl; 
    #endif
    Print_SplitLine('-'); 

    #ifdef DEMO
        std::cout <<"1. generate memo info of CTx" << std::endl;  
    #endif

    auto start_time = std::chrono::steady_clock::now(); 
    newCTx.sn = Acct_sender.sn;
    newCTx.pk_s = Acct_sender.pk; 
    newCTx.pk_r = pk_r; 

    Twisted_ElGamal_PP enc_pp;
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    newCTx.v = v; 
    std::vector<ECPoint> vec_pk = {newCTx.pk_s, newCTx.pk_r, pp.pk_a}; 
    BigInt r = GenRandomBigIntLessThan(order);
    MR_Twisted_ElGamal_Enc(enc_pp, vec_pk, newCTx.v, r, newCTx.transfer_ct); 

    newCTx.sender_balance_ct.X = Acct_sender.balance_ct.X;
    newCTx.sender_balance_ct.Y = Acct_sender.balance_ct.Y;

    #ifdef DEMO
        std::cout << "2. generate NIZKPoK for plaintext equality" << std::endl;  
    #endif
    // begin to generate the valid proof for ctx
    std::string transcript_str = BigIntToHexString(newCTx.sn); 

    // generate NIZK proof for validity of transfer              
    Plaintext_Equality_PP pteq_pp; 
    Get_Plaintext_Equality_PP_from_ADCT_PP(pp, pteq_pp);
    
    Plaintext_Equality_Instance pteq_instance;
     
    pteq_instance.pk1 = newCTx.pk_s; 
    pteq_instance.pk2 = newCTx.pk_r; 
    pteq_instance.pk3 = pp.pk_a; 
    pteq_instance.X1 = newCTx.transfer_ct.X[0];
    pteq_instance.X2 = newCTx.transfer_ct.X[1];
    pteq_instance.X3 = newCTx.transfer_ct.X[2];
    pteq_instance.Y = newCTx.transfer_ct.Y;
    
    Plaintext_Equality_Witness pteq_witness; 
    pteq_witness.r = r; 
    pteq_witness.v = v; 

    NIZK_Plaintext_Equality_Prove(pteq_pp, pteq_instance, pteq_witness, transcript_str, newCTx.plaintext_equality_proof);


    #ifdef DEMO
        std::cout << "3. compute updated balance" << std::endl;  
    #endif
    // compute the updated balance

    Twisted_ElGamal_CT sender_updated_balance_ct; 
    sender_updated_balance_ct.X = newCTx.sender_balance_ct.X - newCTx.transfer_ct.X[0];
    sender_updated_balance_ct.Y = newCTx.sender_balance_ct.Y - newCTx.transfer_ct.Y;     

    #ifdef DEMO
        std::cout << "4. compute refreshed updated balance" << std::endl;  
    #endif
    // refresh the updated balance (with random coins r^*)
    BigInt r_star = GenRandomBigIntLessThan(order);    
    Twisted_ElGamal_ReEnc(enc_pp, Acct_sender.pk, Acct_sender.sk, 
                          sender_updated_balance_ct, r_star, newCTx.refresh_sender_updated_balance_ct);

    #ifdef DEMO
        std::cout << "5. generate NIZKPoK for correct refreshing and authenticate the memo info" << std::endl;  
    #endif
    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_ADCT_PP(pp, dlogeq_pp); 
    
    DLOG_Equality_Instance dlogeq_instance; 
       
    dlogeq_instance.g1 = sender_updated_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; // g1 = Y-Y^* = g^{r-r^*} 
    dlogeq_instance.h1 = sender_updated_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; // h1 = X-X^* = pk^{r-r^*}
    
    dlogeq_instance.g2 = enc_pp.g;                         // g2 = g
    dlogeq_instance.h2 = Acct_sender.pk;                    // h2 = pk  
    DLOG_Equality_Witness dlogeq_witness;  
    dlogeq_witness.w = Acct_sender.sk; 

    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, newCTx.dlog_equality_proof); 


    #ifdef DEMO
        std::cout << "6. generate NIZKPoK for refreshed updated balance" << std::endl;  
    #endif
    Plaintext_Knowledge_PP ptke_pp;
    Get_Plaintext_Knowledge_PP_from_ADCT_PP(pp, ptke_pp);

    Plaintext_Knowledge_Instance ptke_instance; 

    ptke_instance.pk = Acct_sender.pk; 
    ptke_instance.X = newCTx.refresh_sender_updated_balance_ct.X; 
    ptke_instance.Y = newCTx.refresh_sender_updated_balance_ct.Y; 
    
    Plaintext_Knowledge_Witness ptke_witness; 
    ptke_witness.r = r_star; 
    ptke_witness.v = Acct_sender.m - v; 

    NIZK_Plaintext_Knowledge_Prove(ptke_pp, ptke_instance, ptke_witness, 
                                   transcript_str, newCTx.plaintext_knowledge_proof); 

    #ifdef DEMO
        std::cout << "7. generate range proofs for transfer amount and updated balance" << std::endl;    
    #endif
    
    // aggregated range proof for v and m-v lie in the right range 
    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_ADCT_PP(pp, bullet_pp);

    // std::cout << pp.vec_g.size() << std::endl; 
    // std::cout << pp.vec_h.size() << std::endl; 

    // std::cout << bullet_pp.vec_g.size() << std::endl; 
    // std::cout << bullet_pp.vec_h.size() << std::endl; 

    Bullet_Instance bullet_instance;
    bullet_instance.C = {newCTx.transfer_ct.Y, newCTx.refresh_sender_updated_balance_ct.Y};

    Bullet_Witness bullet_witness;  
    bullet_witness.r = {pteq_witness.r, ptke_witness.r}; 
    bullet_witness.v = {pteq_witness.v, ptke_witness.v};

    Bullet_Prove(bullet_pp, bullet_instance, bullet_witness, transcript_str, newCTx.bullet_right_solvent_proof); 


    #ifdef DEMO
        Print_SplitLine('-'); 
    #endif

    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "ctx generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

/* check if the given confidential transaction is valid */ 
bool ADCT_Verify_CTx(ADCT_PP &pp, ADCT_CTx &newCTx)
{     
    #ifdef DEMO
        std::cout << "begin to verify CTx >>>>>>" << std::endl; 
    #endif

    auto start_time = std::chrono::steady_clock::now(); 
    
    bool Validity; 
    bool V1, V2, V3, V4; 

    std::string transcript_str = BigIntToHexString(newCTx.sn); 

    Plaintext_Equality_PP pteq_pp;
    Get_Plaintext_Equality_PP_from_ADCT_PP(pp, pteq_pp); 

    Plaintext_Equality_Instance pteq_instance; 
    pteq_instance.pk1 = newCTx.pk_s;
    pteq_instance.pk2 = newCTx.pk_r;
    pteq_instance.pk3 = pp.pk_a;
    pteq_instance.X1 = newCTx.transfer_ct.X[0];
    pteq_instance.X2 = newCTx.transfer_ct.X[1];
    pteq_instance.X3 = newCTx.transfer_ct.X[2];
    pteq_instance.Y = newCTx.transfer_ct.Y;

    V1 = NIZK_Plaintext_Equality_Verify(pteq_pp, pteq_instance, transcript_str, newCTx.plaintext_equality_proof);
    

    #ifdef DEMO
        if (V1) std::cout << "NIZKPoK for plaintext equality accepts" << std::endl; 
        else std::cout << "NIZKPoK for plaintext equality rejects" << std::endl; 
    #endif

    // check V2
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    Twisted_ElGamal_CT updated_sender_balance_ct; 
    updated_sender_balance_ct.X = newCTx.sender_balance_ct.X - newCTx.transfer_ct.X[0]; 
    updated_sender_balance_ct.Y = newCTx.sender_balance_ct.Y - newCTx.transfer_ct.Y; 

    // generate the NIZK proof for updated balance and fresh updated balance encrypt the same message
    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_ADCT_PP(pp, dlogeq_pp);

    DLOG_Equality_Instance dlogeq_instance; 

    dlogeq_instance.g1 = updated_sender_balance_ct.Y - newCTx.refresh_sender_updated_balance_ct.Y; 
    dlogeq_instance.h1 = updated_sender_balance_ct.X - newCTx.refresh_sender_updated_balance_ct.X; 
    dlogeq_instance.g2 = enc_pp.g; 
    dlogeq_instance.h2 = newCTx.pk_s;  

    V2 = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, transcript_str, newCTx.dlog_equality_proof); 

    #ifdef DEMO
        if (V2) std::cout << "NIZKPoK for refreshing correctness accepts and memo info is authenticated" << std::endl; 
        else std::cout << "NIZKPoK for refreshing correctness rejects or memo info is unauthenticated" << std::endl; 
    #endif

    Plaintext_Knowledge_PP ptke_pp; 
    Get_Plaintext_Knowledge_PP_from_ADCT_PP(pp, ptke_pp);

    Plaintext_Knowledge_Instance ptke_instance; 
    ptke_instance.pk = newCTx.pk_s; 
    ptke_instance.X = newCTx.refresh_sender_updated_balance_ct.X; 
    ptke_instance.Y = newCTx.refresh_sender_updated_balance_ct.Y; 

    V3 = NIZK_Plaintext_Knowledge_Verify(ptke_pp, ptke_instance, transcript_str, newCTx.plaintext_knowledge_proof);

    #ifdef DEMO
        if (V3) std::cout << "NIZKPoK for refresh updated balance accepts" << std::endl; 
        else std::cout << "NIZKPoK for refresh updated balance rejects" << std::endl; 
    #endif

    // aggregated range proof for v and m-v lie in the right range 
    Bullet_PP bullet_pp; 
    Get_Bullet_PP_from_ADCT_PP(pp, bullet_pp);

    Bullet_Instance bullet_instance;
    bullet_instance.C = {newCTx.transfer_ct.Y, newCTx.refresh_sender_updated_balance_ct.Y};

    V4 = Bullet_Verify(bullet_pp, bullet_instance, transcript_str, newCTx.bullet_right_solvent_proof); 

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
bool ADCT_Miner(ADCT_PP &pp, ADCT_CTx &newCTx, ADCT_Account &Acct_sender, ADCT_Account &Acct_receiver)
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
    if(ADCT_Verify_CTx(pp, newCTx) == true){
        ADCT_Update_Account(pp, newCTx, Acct_sender, Acct_receiver);
        ADCT_Save_CTx(newCTx, ctx_file);  
        std::cout << ctx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << ctx_file << " is discarded" << std::endl; 
        return false; 
    }
}


/* support more policies */

struct Limit_Policy{
    BigInt LEFT_BOUND;  // the transfer limit 
    BigInt RIGHT_BOUND; 
};

struct Rate_Policy{
    BigInt t1, t2;  // the tax rate = t1/t2
};

struct Open_Policy{
    BigInt v;   // the hidden value = v
}; 


/* generate a NIZK proof for CT = Enc(pk, v; r)  */
bool ADCT_Justify_Open_Policy(ADCT_PP &pp, ADCT_Account &Acct_user, ADCT_CTx &doubtCTx, 
                              Open_Policy &policy, DLOG_Equality_Proof &open_proof)
{
    if ((Acct_user.pk != doubtCTx.pk_s) && (Acct_user.pk != doubtCTx.pk_r)) {
        std::cout << "the identity of claimer does not match ctx" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    DLOG_Equality_PP dlogeq_pp;
    Get_DLOG_Equality_PP_from_ADCT_PP(pp, dlogeq_pp); 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    DLOG_Equality_Instance dlogeq_instance;  
    
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
    DLOG_Equality_Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_user.sk; 

    std::string transcript_str = ""; 
    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, open_proof); 
    
    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for open policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return true; 
} 

/* check if the proposed NIZK proof PI for open policy is valid */ 
bool ADCT_Audit_Open_Policy(ADCT_PP &pp, ADCT_Account &Acct_user, ADCT_CTx &doubtCTx,  
                            Open_Policy &policy, DLOG_Equality_Proof &open_proof)
{ 
    if ((Acct_user.pk != doubtCTx.pk_s) && (Acct_user.pk != doubtCTx.pk_r)){
        std::cout << "the identity of claimer does not match ctx" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 

    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_ADCT_PP(pp, dlogeq_pp); 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    DLOG_Equality_Instance dlogeq_instance; 
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
    validity = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, transcript_str, open_proof); 

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
bool ADCT_Justify_Rate_Policy(ADCT_PP &pp, ADCT_Account &Acct_user, ADCT_CTx &ctx1, ADCT_CTx &ctx2,  
                             Rate_Policy &policy, DLOG_Equality_Proof &rate_proof)
{
    if (Acct_user.pk != ctx1.pk_r || Acct_user.pk != ctx2.pk_s){
        std::cout << "the identity of claimer does not match" << std::endl; 
        return false; 
    }

    auto start_time = std::chrono::steady_clock::now(); 
    
    DLOG_Equality_PP dlogeq_pp;
    Get_DLOG_Equality_PP_from_ADCT_PP(pp, dlogeq_pp); 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    DLOG_Equality_Instance dlogeq_instance; 
    dlogeq_instance.g1 = enc_pp.g;     // g1 = g 
    dlogeq_instance.h1 = Acct_user.pk; // g2 = pk = g^sk

    Twisted_ElGamal_CT ct_in; 
    ct_in.X = ctx1.transfer_ct.X[1]; 
    ct_in.Y = ctx1.transfer_ct.Y; 
    Twisted_ElGamal_ScalarMul(ct_in, ct_in, policy.t1); 
    
    Twisted_ElGamal_CT ct_out; 
    ct_out.X = ctx2.transfer_ct.X[0]; 
    ct_out.Y = ctx2.transfer_ct.Y; 
    Twisted_ElGamal_ScalarMul(ct_out, ct_out, policy.t2); 

    Twisted_ElGamal_CT ct_diff;  
    Twisted_ElGamal_HomoSub(ct_diff, ct_in, ct_out);  

    dlogeq_instance.g2 = ct_diff.Y; 
    dlogeq_instance.h2 = ct_diff.X; 

    DLOG_Equality_Witness dlogeq_witness; 
    dlogeq_witness.w = Acct_user.sk; 

    std::string transcript_str = ""; 
    NIZK_DLOG_Equality_Prove(dlogeq_pp, dlogeq_instance, dlogeq_witness, transcript_str, rate_proof); 

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for rate policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return true; 
} 

/* check if the NIZK proof PI for rate policy is valid */
bool ADCT_Audit_Rate_Policy(ADCT_PP &pp, ECPoint pk, ADCT_CTx &ctx1, ADCT_CTx &ctx2,  
                            Rate_Policy &policy, DLOG_Equality_Proof &rate_proof)
{ 
    if ((pk != ctx1.pk_r) || (pk != ctx2.pk_s)){
        std::cout << "the identity of claimer does not match" << std::endl; 
        return false; 
    }
    
    auto start_time = std::chrono::steady_clock::now(); 
    
    DLOG_Equality_PP dlogeq_pp; 
    Get_DLOG_Equality_PP_from_ADCT_PP(pp, dlogeq_pp); 
    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 

    DLOG_Equality_Instance dlogeq_instance; 
    dlogeq_instance.g1 = enc_pp.g;     // g1 = g 
    dlogeq_instance.h1 = pk; // g2 = pk = g^sk

    Twisted_ElGamal_CT ct_in; 
    ct_in.X = ctx1.transfer_ct.X[1]; 
    ct_in.Y = ctx1.transfer_ct.Y; 
    Twisted_ElGamal_ScalarMul(ct_in, ct_in, policy.t1); 
    
    Twisted_ElGamal_CT ct_out; 
    ct_out.X = ctx2.transfer_ct.X[0]; 
    ct_out.Y = ctx2.transfer_ct.Y; 
    Twisted_ElGamal_ScalarMul(ct_out, ct_out, policy.t2);  

    Twisted_ElGamal_CT ct_diff;  
    Twisted_ElGamal_HomoSub(ct_diff, ct_in, ct_out);  

    dlogeq_instance.g2 = ct_diff.Y; 
    dlogeq_instance.h2 = ct_diff.X; 

    std::string transcript_str = ""; 
    bool validity = NIZK_DLOG_Equality_Verify(dlogeq_pp, dlogeq_instance, transcript_str, rate_proof); 

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
bool ADCT_Justify_Limit_Policy(ADCT_PP &pp, ADCT_Account &Acct_user, std::vector<ADCT_CTx> &ctx_set, 
                               Limit_Policy &policy, Gadget2_Proof &limit_proof)
{
    for(auto i = 0; i < ctx_set.size(); i++){
        if (Acct_user.pk != ctx_set[i].pk_s){
            std::cout << "the identity of claimer does not match" << std::endl; 
            return false; 
        }
    }

    auto start_time = std::chrono::steady_clock::now(); 

    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 
    Twisted_ElGamal_CT ct_sum;
    ct_sum.X.SetInfinity();
    ct_sum.Y.SetInfinity(); 
    Twisted_ElGamal_CT ct_temp; 
    for(auto i = 0; i < ctx_set.size(); i++)
    {
        ct_temp.X = ctx_set[i].transfer_ct.X[0]; 
        ct_temp.Y = ctx_set[i].transfer_ct.Y;
        Twisted_ElGamal_HomoAdd(ct_sum, ct_sum, ct_temp); 
    } 
 
    Gadget_PP gadget_pp;
    Get_Gadget_PP_from_ADCT_PP(pp, gadget_pp); 
    Gadget_Instance instance; 
    instance.pk = Acct_user.pk; 
    instance.ct.X = ct_sum.X; instance.ct.Y = ct_sum.Y;  
    Gadget2_Witness witness;
    witness.sk = Acct_user.sk;  

    std::string transcript_str = ""; 

    Gadget2_Prove(gadget_pp, instance, policy.LEFT_BOUND, policy.RIGHT_BOUND, witness, transcript_str, limit_proof); 
    
    auto end_time = std::chrono::steady_clock::now(); 

    auto running_time = end_time - start_time;
    std::cout << "generate NIZK proof for limit policy takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    return true;
} 

/* check if the proposed NIZK proof for limit policy is valid */ 
bool ADCT_Audit_Limit_Policy(ADCT_PP &pp, ECPoint pk, std::vector<ADCT_CTx> &ctx_set, 
                             Limit_Policy &policy, Gadget2_Proof &limit_proof)
{ 
    for(auto i = 0; i < ctx_set.size(); i++){
        if (pk != ctx_set[i].pk_s){
            std::cout << "the identity of claimer does not match" << std::endl; 
            return false; 
        }
    }

    auto start_time = std::chrono::steady_clock::now(); 

    Twisted_ElGamal_PP enc_pp; 
    Get_Enc_PP_from_ADCT_PP(pp, enc_pp); 
    Twisted_ElGamal_CT ct_sum;
    ct_sum.X.SetInfinity();
    ct_sum.Y.SetInfinity(); 
    Twisted_ElGamal_CT ct_temp; 
    for(auto i = 0; i < ctx_set.size(); i++)
    {
        ct_temp.X = ctx_set[i].transfer_ct.X[0]; 
        ct_temp.Y = ctx_set[i].transfer_ct.Y;
        Twisted_ElGamal_HomoAdd(ct_sum, ct_sum, ct_temp); 
    } 
 
    Gadget_PP gadget_pp;
    Get_Gadget_PP_from_ADCT_PP(pp, gadget_pp); 
    Gadget_Instance instance; 
    instance.pk = pk; 
    instance.ct.X = ct_sum.X; instance.ct.Y = ct_sum.Y; 

    std::string transcript_str = ""; 

    bool validity = Gadget2_Verify(gadget_pp, instance,  policy.LEFT_BOUND, policy.RIGHT_BOUND, transcript_str, limit_proof); 

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

#endif