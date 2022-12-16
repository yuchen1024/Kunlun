#include "../adcp/adcp.hpp"
#include "../crypto/setup.hpp"

void Build_ADCP_Test_Enviroment()
{
    PrintSplitLine('-'); 
    std::cout << "build test enviroment for ADCP >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "setup ADCP system" << std::endl; 
    // setup adcp system
    size_t SN_LEN = 4;
    size_t LOG_MAXIMUM_COINS = 32;      
    size_t MAX_RECEIVER_NUM = 7;  

    ADCP::SP sp;
    ADCP::PP pp;

    std::tie(pp, sp) = ADCP::Setup(LOG_MAXIMUM_COINS, MAX_RECEIVER_NUM, SN_LEN); 

    ADCP::Initialize(pp);

    std::string ADCP_SP_Filename = "adcp.sp"; 
    ADCP::SaveSP(sp, ADCP_SP_Filename); 

    std::string adcp_PP_Filename = "adcp.pp"; 
    ADCP::SavePP(pp, adcp_PP_Filename); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");


    // create accounts for Alice and Bob and Tax
    std::cout << "generate four accounts" << std::endl; 
    PrintSplitLine('-'); 

    BigInt Alice_balance = BigInt(512); 
    BigInt Alice_sn = bn_1; 
    ADCP::Account Acct_Alice = ADCP::CreateAccount(pp, "Alice", Alice_balance, Alice_sn); 
    std::string Alice_Acct_FileName = "Alice.account"; 
    ADCP::SaveAccount(Acct_Alice, Alice_Acct_FileName); 

    BigInt Bob_balance = BigInt(256); 
    BigInt Bob_sn = bn_1; 
    ADCP::Account Acct_Bob = ADCP::CreateAccount(pp, "Bob", Bob_balance, Bob_sn); 
    std::string Bob_Acct_FileName = "Bob.account"; 
    ADCP::SaveAccount(Acct_Bob, Bob_Acct_FileName); 

    BigInt Carl_balance = BigInt(128); 
    BigInt Carl_sn = bn_1; 
    ADCP::Account Acct_Carl = ADCP::CreateAccount(pp, "Carl", Carl_balance, Carl_sn); 
    std::string Carl_Acct_FileName = "Carl.account"; 
    ADCP::SaveAccount(Acct_Carl, Carl_Acct_FileName); 

    BigInt Tax_balance = bn_0; 
    BigInt Tax_sn = bn_1; 
    ADCP::Account Acct_Tax = ADCP::CreateAccount(pp, "Tax", Tax_balance, Tax_sn); 
    std::string Tax_Acct_FileName = "Tax.account"; 
    ADCP::SaveAccount(Acct_Tax, Tax_Acct_FileName); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");
} 

void Emulate_ADCP_System()
{
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    
    ADCP::SP sp;  
    ADCP::FetchSP(sp, "adcp.sp"); 

    ADCP::PP pp;  
    ADCP::FetchPP(pp, "adcp.pp"); 
    ADCP::PrintPP(pp); 

    ADCP::Account Acct_Alice;  
    ADCP::FetchAccount(Acct_Alice, "Alice.account"); 
    ADCP::PrintAccount(Acct_Alice); 

    ADCP::Account Acct_Bob;  
    ADCP::FetchAccount(Acct_Bob, "Bob.account"); 
    ADCP::PrintAccount(Acct_Bob); 

    ADCP::Account Acct_Carl;  
    ADCP::FetchAccount(Acct_Carl, "Carl.account"); 
    ADCP::PrintAccount(Acct_Carl); 

    ADCP::Account Acct_Tax;  
    ADCP::FetchAccount(Acct_Tax, "Tax.account"); 
    ADCP::PrintAccount(Acct_Tax); 

    std::cout << "begin to the test of 1-to-1 ctx" << std::endl; 
    PrintSplitLine('-'); 
     
    BigInt v; 

    std::cout << "Wrong Case 1: invalid ctx --- wrong encryption => equality proof will reject" << std::endl;  
    v = BigInt(128);
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCP::ToOneCTx wrong_ctx1 = ADCP::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);

    ECPoint noisy = GenRandomGenerator(); 
    wrong_ctx1.transfer_ct.vec_X[0] = wrong_ctx1.transfer_ct.vec_X[0] + noisy;
    ADCP::Miner(pp, wrong_ctx1, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "Wrong Case 2: invalid ctx --- wrong interval of transfer amount => range proof will reject" << std::endl; 
    v = BigInt(4294967296); 
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCP::ToOneCTx wrong_ctx2 = ADCP::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCP::Miner(pp, wrong_ctx2, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "Wrong Case 3: invalid ctx --- balance is not enough => range proof will reject" << std::endl; 
    v = BigInt(513);  
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCP::ToOneCTx wrong_ctx3 = ADCP::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCP::Miner(pp, wrong_ctx3, Acct_Alice, Acct_Bob);  
    PrintSplitLine('-'); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "1st valid 1-to-1 ctx" << std::endl; 
    v = BigInt(128); 
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCP::ToOneCTx ctx1 = ADCP::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCP::Miner(pp, ctx1, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    std::cout << "after 1st valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::PrintAccount(Acct_Alice); 
    ADCP::PrintAccount(Acct_Bob); 
    ADCP::PrintAccount(Acct_Carl); 
    ADCP::PrintAccount(Acct_Tax); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "2nd valid 1-to-1 ctx" << std::endl; 
    v = BigInt(32);  
    std::cout << "Bob is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Tax" << std::endl; 
    ADCP::ToOneCTx ctx2 = ADCP::CreateCTx(pp, Acct_Bob, v, Acct_Tax.pk);
    ADCP::Miner(pp, ctx2, Acct_Bob, Acct_Tax); 
    PrintSplitLine('-'); 

    std::cout << "after 2nd valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::PrintAccount(Acct_Alice); 
    ADCP::PrintAccount(Acct_Bob); 
    ADCP::PrintAccount(Acct_Carl); 
    ADCP::PrintAccount(Acct_Tax); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "3nd valid 1-to-1 ctx" << std::endl; 
    v = BigInt(384);  
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCP::ToOneCTx ctx3 = ADCP::CreateCTx(pp, Acct_Alice, v, Acct_Bob.pk);
    ADCP::Miner(pp, ctx3, Acct_Alice, Acct_Bob); 
    PrintSplitLine('-'); 

    std::cout << "after 3nd valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::PrintAccount(Acct_Alice); 
    ADCP::PrintAccount(Acct_Bob); 
    ADCP::PrintAccount(Acct_Carl); 
    ADCP::PrintAccount(Acct_Tax); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "4th valid 1-to-1 ctx" << std::endl; 
    v = BigInt(128);  
    std::cout << "Carl is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Tax" << std::endl; 
    ADCP::ToOneCTx ctx4 = ADCP::CreateCTx(pp, Acct_Carl, v, Acct_Tax.pk);
    ADCP::Miner(pp, ctx4, Acct_Carl, Acct_Tax); 
    PrintSplitLine('-'); 

    std::cout << "after 4th valid 1-to-1 ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::PrintAccount(Acct_Alice); 
    ADCP::PrintAccount(Acct_Bob); 
    ADCP::PrintAccount(Acct_Carl); 
    ADCP::PrintAccount(Acct_Tax); 


    std::cout << "supervision of 1-to-1 ctx begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::SuperviseCTx(sp, pp, ctx1); 
    PrintSplitLine('-'); 
    ADCP::SuperviseCTx(sp, pp, ctx2);
    PrintSplitLine('-'); 
    ADCP::SuperviseCTx(sp, pp, ctx3);
    PrintSplitLine('-');  
    std::cout << "supervision of 1-to-1 ctx ends >>>" << std::endl; 
    PrintSplitLine('-');


    std::cout << "audit begins >>>" << std::endl;

    PrintSplitLine('-'); 
    ADCP::OpenPolicy open_policy; 
    open_policy.v = 128; 
    DLOGEquality::Proof open_proof = ADCP::JustifyPolicy(pp, Acct_Alice, ctx1, open_policy);
    ADCP::AuditPolicy(pp, Acct_Alice, ctx1, open_policy, open_proof); 
    
    // suppose the tax ratio is 25%
    PrintSplitLine('-'); 
    ADCP::RatePolicy rate_policy; 
    rate_policy.t1 = BigInt(1); rate_policy.t2 = BigInt(4);  
    DLOGEquality::Proof rate_proof = ADCP::JustifyPolicy(pp, Acct_Bob, ctx1, ctx2, rate_policy); 
    ADCP::AuditPolicy(pp, Acct_Bob.pk, ctx1, ctx2, rate_policy, rate_proof);

    // check the limit policy LEFT_BOUND < value <= RIGHT_BOUND 
    PrintSplitLine('-');  
    ADCP::LimitPolicy limit_policy; 
    limit_policy.LEFT_BOUND = bn_0; limit_policy.RIGHT_BOUND = BigInt(513);  
    std::vector<ADCP::ToOneCTx> ctx_set = {ctx1, ctx3}; 
    Gadget::Proof_type2 limit_proof; 
    ADCP::JustifyPolicy(pp, Acct_Alice, ctx_set, limit_policy, limit_proof); 
    ADCP::AuditPolicy(pp, Acct_Alice.pk, ctx_set, limit_policy, limit_proof);
    
    PrintSplitLine('-'); 
    std::cout << "audit ends >>>" << std::endl; 
    PrintSplitLine('-');

    std::cout << "press any key to continue >>>" << std::endl; 
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
    std::vector<ADCP::Account> vec_Acct_receiver = {Acct_Alice, Acct_Bob, Acct_Carl};  

    ADCP::ToManyCTx ctx5 = ADCP::CreateCTx(pp, Acct_Tax, vec_v, vec_pkr);
    ADCP::Miner(pp, ctx5, Acct_Tax, vec_Acct_receiver); 
    PrintSplitLine('-'); 

    std::cout << "after 1st valid 1-to-n ctx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::PrintAccount(Acct_Alice); 
    ADCP::PrintAccount(Acct_Bob); 
    ADCP::PrintAccount(Acct_Carl); 
    ADCP::PrintAccount(Acct_Tax); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "supervision of 1-to-n ctx begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    ADCP::SuperviseCTx(sp, pp, ctx5); 
    PrintSplitLine('-'); 
    std::cout << "supervision of 1-to-n ctx ends >>>" << std::endl; 
    PrintSplitLine('-');

}



int main()
{
    CRYPTO_Initialize();   

    Build_ADCP_Test_Enviroment(); 
    Emulate_ADCP_System();

    CRYPTO_Finalize(); 

    return 0; 
}



