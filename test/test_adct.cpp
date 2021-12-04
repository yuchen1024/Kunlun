#include "../adct/adct.hpp"

void Build_ADCT_Test_Enviroment()
{
    PrintSplitLine('-'); 
    std::cout << "build test enviroment for ADCT >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "setup ADCT system" << std::endl; 
    // setup ADCT system
    size_t SN_LEN = 4;
    size_t LOG_MAXIMUM_COINS = 32;      
    size_t MAX_RECEIVER_NUM = 7;  

    ADCT::SP sp;
    ADCT::PP pp;

    std::tie(pp, sp) = ADCT::Setup(LOG_MAXIMUM_COINS, MAX_RECEIVER_NUM, SN_LEN); 

    ADCT::Initialize(pp);

    std::string ADCT_SP_Filename = "ADCT.sp"; 
    ADCT::SaveSP(sp, ADCT_SP_Filename); 

    std::string ADCT_PP_Filename = "ADCT.pp"; 
    ADCT::SavePP(pp, ADCT_PP_Filename); 

    system ("read");

    // create accounts for Alice and Bob and Tax
    std::cout << "generate four accounts" << std::endl; 
    PrintSplitLine('-'); 

    BigInt Alice_balance = BigInt(512); 
    BigInt Alice_sn = bn_1; 
    ADCT::Account Acct_Alice = ADCT::CreateAccount(pp, "Alice", Alice_balance, Alice_sn); 
    std::string Alice_Acct_FileName = "Alice.account"; 
    ADCT::SaveAccount(Acct_Alice, Alice_Acct_FileName); 

    BigInt Bob_balance = BigInt(256); 
    BigInt Bob_sn = bn_1; 
    ADCT::Account Acct_Bob = ADCT::CreateAccount(pp, "Bob", Bob_balance, Bob_sn); 
    std::string Bob_Acct_FileName = "Bob.account"; 
    ADCT::SaveAccount(Acct_Bob, Bob_Acct_FileName); 

    BigInt Carl_balance = BigInt(128); 
    BigInt Carl_sn = bn_1; 
    ADCT::Account Acct_Carl = ADCT::CreateAccount(pp, "Carl", Carl_balance, Carl_sn); 
    std::string Carl_Acct_FileName = "Carl.account"; 
    ADCT::SaveAccount(Acct_Carl, Carl_Acct_FileName); 

    BigInt Tax_balance = bn_0; 
    BigInt Tax_sn = bn_1; 
    ADCT::Account Acct_Tax = ADCT::CreateAccount(pp, "Tax", Tax_balance, Tax_sn); 
    std::string Tax_Acct_FileName = "Tax.account"; 
    ADCT::SaveAccount(Acct_Tax, Tax_Acct_FileName); 

    system ("read");
} 

void Emulate_ADCT_System()
{
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    
    ADCT::SP sp;  
    ADCT::FetchSP(sp, "ADCT.sp"); 

    ADCT::PP pp;  
    ADCT::FetchPP(pp, "ADCT.pp"); 

    ADCT::Account Acct_Alice;  
    ADCT::FetchAccount(Acct_Alice, "Alice.account"); 
    ADCT::PrintAccount(Acct_Alice); 

    ADCT::Account Acct_Bob;  
    ADCT::FetchAccount(Acct_Bob, "Bob.account"); 
    ADCT::PrintAccount(Acct_Bob); 

    ADCT::Account Acct_Carl;  
    ADCT::FetchAccount(Acct_Carl, "Carl.account"); 
    ADCT::PrintAccount(Acct_Carl); 

    ADCT::Account Acct_Tax;  
    ADCT::FetchAccount(Acct_Tax, "Tax.account"); 
    ADCT::PrintAccount(Acct_Tax); 

    std::cout << "begin to the test of 1-to-1 ctx" << std::endl; 
    PrintSplitLine('-'); 
     
    BigInt v; 

    std::cout << "Wrong Case 1: invalid ctx --- wrong encryption => equality proof will reject" << std::endl;  
    v = BigInt(128);
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT::ToOneCTx wrong_ctx1 = ADCT::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);

    ECPoint noisy = GenRandomGenerator(); 
    wrong_ctx1.transfer_ct.vec_X[0] = wrong_ctx1.transfer_ct.vec_X[0] + noisy;
    ADCT::Miner(pp, wrong_ctx1, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    system("read");

    std::cout << "Wrong Case 2: invalid ctx --- wrong interval of transfer amount => range proof will reject" << std::endl; 
    v = BigInt(4294967296); 
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT::ToOneCTx wrong_ctx2 = ADCT::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCT::Miner(pp, wrong_ctx2, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    system ("read");

    std::cout << "Wrong Case 3: invalid ctx --- balance is not enough => range proof will reject" << std::endl; 
    v = BigInt(513);  
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT::ToOneCTx wrong_ctx3 = ADCT::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCT::Miner(pp, wrong_ctx3, Acct_Alice, Acct_Bob);  
    PrintSplitLine('-'); 

    system("read");

    std::cout << "1st valid 1-to-1 ctx" << std::endl; 
    v = BigInt(128); 
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT::ToOneCTx ctx1 = ADCT::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCT::Miner(pp, ctx1, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    std::cout << "after 1st valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::PrintAccount(Acct_Alice); 
    ADCT::PrintAccount(Acct_Bob); 
    ADCT::PrintAccount(Acct_Carl); 
    ADCT::PrintAccount(Acct_Tax); 

    system("read");

    std::cout << "2nd valid 1-to-1 ctx" << std::endl; 
    v = BigInt(32);  
    std::cout << "Bob is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Tax" << std::endl; 
    ADCT::ToOneCTx ctx2 = ADCT::CreateCTx(pp, Acct_Bob, v, Acct_Tax.pk);
    ADCT::Miner(pp, ctx2, Acct_Bob, Acct_Tax); 
    PrintSplitLine('-'); 

    std::cout << "after 2nd valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::PrintAccount(Acct_Alice); 
    ADCT::PrintAccount(Acct_Bob); 
    ADCT::PrintAccount(Acct_Carl); 
    ADCT::PrintAccount(Acct_Tax); 

    system("read");

    std::cout << "3nd valid 1-to-1 ctx" << std::endl; 
    v = BigInt(384);  
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT::ToOneCTx ctx3 = ADCT::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCT::Miner(pp, ctx3, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    std::cout << "after 3nd valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::PrintAccount(Acct_Alice); 
    ADCT::PrintAccount(Acct_Bob); 
    ADCT::PrintAccount(Acct_Carl); 
    ADCT::PrintAccount(Acct_Tax); 

    system("read"); 
    std::cout << "4th valid 1-to-1 ctx" << std::endl; 
    v = BigInt(128);  
    std::cout << "Carl is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Tax" << std::endl; 
    ADCT::ToOneCTx ctx4 = ADCT::CreateCTx(pp, Acct_Carl, v, Acct_Tax.pk);
    ADCT::Miner(pp, ctx4, Acct_Carl, Acct_Tax); 
    PrintSplitLine('-'); 

    std::cout << "after 4th valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::PrintAccount(Acct_Alice); 
    ADCT::PrintAccount(Acct_Bob); 
    ADCT::PrintAccount(Acct_Carl); 
    ADCT::PrintAccount(Acct_Tax); 


    std::cout << "supervision of 1-to-1 ctx begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::SuperviseCTx(sp, pp, ctx1); 
    PrintSplitLine('-'); 
    ADCT::SuperviseCTx(sp, pp, ctx2);
    PrintSplitLine('-'); 
    ADCT::SuperviseCTx(sp, pp, ctx3);
    PrintSplitLine('-');  
    std::cout << "supervision of 1-to-1 ctx ends >>>" << std::endl; 
    PrintSplitLine('-');


    std::cout << "audit begins >>>" << std::endl;

    PrintSplitLine('-'); 
    ADCT::OpenPolicy open_policy; 
    open_policy.v = 128; 
    DLOGEquality::Proof open_proof = ADCT::JustifyPolicy(pp, Acct_Alice, ctx1, open_policy);
    ADCT::AuditPolicy(pp, Acct_Alice, ctx1, open_policy, open_proof); 
    
    // suppose the tax ratio is 25%
    PrintSplitLine('-'); 
    ADCT::RatePolicy rate_policy; 
    rate_policy.t1 = BigInt(1); rate_policy.t2 = BigInt(4);  
    DLOGEquality::Proof rate_proof = ADCT::JustifyPolicy(pp, Acct_Bob, ctx1, ctx2, rate_policy); 
    ADCT::AuditPolicy(pp, Acct_Bob.pk, ctx1, ctx2, rate_policy, rate_proof);

    // check the limit policy LEFT_BOUND < value <= RIGHT_BOUND 
    PrintSplitLine('-');  
    ADCT::LimitPolicy limit_policy; 
    limit_policy.LEFT_BOUND = bn_0; limit_policy.RIGHT_BOUND = BigInt(513);  
    std::vector<ADCT::ToOneCTx> ctx_set = {ctx1, ctx3}; 
    Gadget::Proof_type2 limit_proof; 
    ADCT::JustifyPolicy(pp, Acct_Alice, ctx_set, limit_policy, limit_proof); 
    ADCT::AuditPolicy(pp, Acct_Alice.pk, ctx_set, limit_policy, limit_proof);
    
    PrintSplitLine('-'); 
    std::cout << "audit ends >>>" << std::endl; 
    PrintSplitLine('-');

    system ("read");

    std::cout << "begin the test of 1-to-n ctx" << std::endl;
    std::vector<BigInt> vec_v(3); 
    vec_v[0] = BigInt(16);
    vec_v[1] = BigInt(32);
    vec_v[2] = BigInt(64);

    std::cout << "Tax is going to transfer "<< std::endl; 
    std::cout << BN_bn2dec(vec_v[0].bn_ptr) << " coins to Alice" << std::endl; 
    std::cout << BN_bn2dec(vec_v[1].bn_ptr) << " coins to Bob" << std::endl; 
    std::cout << BN_bn2dec(vec_v[2].bn_ptr) << " coins to Carl" << std::endl;

    std::vector<ECPoint> vec_pkr = {Acct_Alice.pk, Acct_Bob.pk, Acct_Carl.pk};  
    std::vector<ADCT::Account> vec_Acct_receiver = {Acct_Alice, Acct_Bob, Acct_Carl};  

    ADCT::ToManyCTx ctx5 = ADCT::CreateCTx(pp, Acct_Tax, vec_v, vec_pkr);
    ADCT::Miner(pp, ctx5, Acct_Tax, vec_Acct_receiver); 
    PrintSplitLine('-'); 

    std::cout << "after 1st valid 1-to-n ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::PrintAccount(Acct_Alice); 
    ADCT::PrintAccount(Acct_Bob); 
    ADCT::PrintAccount(Acct_Carl); 
    ADCT::PrintAccount(Acct_Tax); 

    system("read");

    std::cout << "supervision of 1-to-n ctx begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCT::SuperviseCTx(sp, pp, ctx5); 
    PrintSplitLine('-'); 
    std::cout << "supervision of 1-to-n ctx ends >>>" << std::endl; 
    PrintSplitLine('-');

}



int main()
{
    Context_Initialize(); 
    ECGroup_Initialize(NID_X9_62_prime256v1);   

    Build_ADCT_Test_Enviroment(); 
    Emulate_ADCT_System();

    ECGroup_Finalize(); 
    Context_Finalize(); 

    return 0; 
}



