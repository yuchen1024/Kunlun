#include "../cryptocurrency/adct.hpp"

void Build_ADCT_Test_Enviroment()
{
    Print_SplitLine('-'); 
    std::cout << "build test enviroment for ADCT >>>" << std::endl; 
    Print_SplitLine('-'); 
    std::cout << "setup ADCT system" << std::endl; 
    // setup ADCT system
    size_t SN_LEN = 4;
    size_t THREAD_NUM = 4;      
    size_t TRADEOFF_NUM = 7; 
    size_t RANGE_LEN = 32;
    size_t AGG_NUM = 2;  

    ADCT_SP sp;
    ADCT_PP pp;

    ADCT_Setup(sp, pp, RANGE_LEN, AGG_NUM, SN_LEN, THREAD_NUM, TRADEOFF_NUM); 

    ADCT_Initialize(pp);

    std::string ADCT_SP_Filename = "ADCT.sp"; 
    ADCT_Save_SP(sp, ADCT_SP_Filename); 

    std::string ADCT_PP_Filename = "ADCT.pp"; 
    ADCT_Save_PP(pp, ADCT_PP_Filename); 

    system ("read");

    // create accounts for Alice and Bob
    std::cout << "generate two accounts" << std::endl; 
    Print_SplitLine('-'); 

    BigInt Alice_balance = BigInt(512); 
    BigInt Alice_sn = bn_1; 
    ADCT_Account Acct_Alice;  
    ADCT_Create_Account(pp, "Alice", Alice_balance, Alice_sn, Acct_Alice); 
    std::string Alice_Acct_FileName = "Alice.account"; 
    ADCT_Save_Account(Acct_Alice, Alice_Acct_FileName); 

    BigInt Bob_balance = BigInt(256); 
    BigInt Bob_sn = bn_1; 
    ADCT_Account Acct_Bob;  
    ADCT_Create_Account(pp, "Bob", Bob_balance, Bob_sn, Acct_Bob); 
    std::string Bob_Acct_FileName = "Bob.account"; 
    ADCT_Save_Account(Acct_Bob, Bob_Acct_FileName); 

    BigInt Tax_balance = bn_0; 
    BigInt Tax_sn = bn_1; 
    ADCT_Account Acct_Tax;  
    ADCT_Create_Account(pp, "Tax", Tax_balance, Tax_sn, Acct_Tax); 
    std::string Tax_Acct_FileName = "Tax.account"; 
    ADCT_Save_Account(Acct_Tax, Tax_Acct_FileName); 

    system ("read");
} 

void Emulate_ADCT_System()
{
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    
    ADCT_SP sp;  
    ADCT_Fetch_SP(sp, "ADCT.sp"); 

    ADCT_PP pp;  
    ADCT_Fetch_PP(pp, "ADCT.pp"); 

    ADCT_Account Acct_Alice;  
    ADCT_Fetch_Account(Acct_Alice, "Alice.account"); 
    ADCT_Print_Account(Acct_Alice); 

    ADCT_Account Acct_Bob;  
    ADCT_Fetch_Account(Acct_Bob, "Bob.account"); 
    ADCT_Print_Account(Acct_Bob); 

    ADCT_Account Acct_Tax;  
    ADCT_Fetch_Account(Acct_Tax, "Tax.account"); 
    ADCT_Print_Account(Acct_Tax); 

    std::cout << "begin to emulate transactions between Alice and Bob" << std::endl; 
    Print_SplitLine('-'); 
    // cout << "before transactions >>>" << endl; 
    // SplitLine_print('-');
     
    BigInt v; 

    std::cout << "Wrong Case 1: Invalid CTx --- wrong encryption => equality proof will reject" << std::endl; 
    ADCT_CTx wrong_ctx1;  
    v = BigInt(128);
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, wrong_ctx1);

    ECPoint noisy = GenRandomGenerator(); 
    wrong_ctx1.transfer_ct.X[0] = wrong_ctx1.transfer_ct.X[0] + noisy;
    ADCT_Miner(pp, wrong_ctx1, Acct_Alice, Acct_Bob); 
    Print_SplitLine('-'); 

    system ("read");

    std::cout << "Wrong Case 2: Invalid CTx --- wrong interval of transfer amount => range proof will reject" << std::endl; 
    ADCT_CTx wrong_ctx2;  
    v = BigInt(4294967296); 
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, wrong_ctx2);
    ADCT_Miner(pp, wrong_ctx2, Acct_Alice, Acct_Bob); 
    Print_SplitLine('-'); 

    system ("read");

    std::cout << "Wrong Case 3: Invalid CTx --- balance is not enough => range proof will reject" << std::endl; 
    ADCT_CTx wrong_ctx3; 
    v = BigInt(513);  
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, wrong_ctx3);
    ADCT_Miner(pp, wrong_ctx3, Acct_Alice, Acct_Bob);  
    Print_SplitLine('-'); 

    system ("read");

    std::cout << "1st valid CTx" << std::endl;
    ADCT_CTx ctx1;  
    v = BigInt(128); 
    std::cout << "alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, ctx1);
    ADCT_Miner(pp, ctx1, Acct_Alice, Acct_Bob); 
    Print_SplitLine('-'); 

    std::cout << "after 1st valid transaction >>>>>>" << std::endl; 
    Print_SplitLine('-'); 
    ADCT_Print_Account(Acct_Alice); 
    ADCT_Print_Account(Acct_Bob); 
    ADCT_Print_Account(Acct_Tax); 

    system ("read");

    std::cout << "2nd Valid CTx" << std::endl; 
    ADCT_CTx ctx2; 
    v = BigInt(32);  
    std::cout << "Bob is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Tax" << std::endl; 
    ADCT_Create_CTx(pp, Acct_Bob, v, Acct_Tax.pk, ctx2);
    ADCT_Miner(pp, ctx2, Acct_Bob, Acct_Tax); 
    Print_SplitLine('-'); 

    std::cout << "after 2nd valid transaction >>>>>>" << std::endl; 
    Print_SplitLine('-'); 
    ADCT_Print_Account(Acct_Alice); 
    ADCT_Print_Account(Acct_Bob); 
    ADCT_Print_Account(Acct_Tax); 

    system ("read");

    std::cout << "3nd Valid CTx" << std::endl; 
    ADCT_CTx ctx3; 
    v = BigInt(384);  
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl; 
    ADCT_Create_CTx(pp, Acct_Alice, v, Acct_Bob.pk, ctx3);
    ADCT_Miner(pp, ctx3, Acct_Alice, Acct_Bob); 
    Print_SplitLine('-'); 

    std::cout << "after 3nd valid transaction >>>>>>" << std::endl; 
    Print_SplitLine('-'); 
    ADCT_Print_Account(Acct_Alice); 
    ADCT_Print_Account(Acct_Bob); 
    ADCT_Print_Account(Acct_Tax); 

    std::cout << "supervision begins >>>" << std::endl; 
    Print_SplitLine('-'); 
    ADCT_Supervise_CTx(sp, pp, ctx1); 
    Print_SplitLine('-'); 
    ADCT_Supervise_CTx(sp, pp, ctx2);
    Print_SplitLine('-'); 
    ADCT_Supervise_CTx(sp, pp, ctx3);
    Print_SplitLine('-');  
    std::cout << "supervision ends >>>" << std::endl; 
    Print_SplitLine('-');


    std::cout << "audit begins >>>" << std::endl;

    Print_SplitLine('-'); 
    Open_Policy open_policy; 
    open_policy.v = 128; 
    DLOG_Equality_Proof open_proof; 
    ADCT_Justify_Open_Policy(pp, Acct_Alice, ctx1, open_policy, open_proof);
    ADCT_Audit_Open_Policy(pp, Acct_Alice, ctx1, open_policy, open_proof); 
    
    Print_SplitLine('-'); 
    Rate_Policy rate_policy; 
    rate_policy.t1 = BigInt(1); rate_policy.t2 = BigInt(4);  
    DLOG_Equality_Proof rate_proof; 
    ADCT_Justify_Rate_Policy(pp, Acct_Bob, ctx1, ctx2, rate_policy, rate_proof); 
    ADCT_Audit_Rate_Policy(pp, Acct_Bob.pk, ctx1, ctx2, rate_policy, rate_proof);

    Print_SplitLine('-');  
    Limit_Policy limit_policy; 
    limit_policy.LEFT_BOUND = bn_0; limit_policy.RIGHT_BOUND = BigInt(513);  
    std::vector<ADCT_CTx> ctx_set = {ctx1, ctx3}; 
    Gadget2_Proof limit_proof; 
    ADCT_Justify_Limit_Policy(pp, Acct_Alice, ctx_set, limit_policy, limit_proof); 
    ADCT_Audit_Limit_Policy(pp, Acct_Alice.pk, ctx_set, limit_policy, limit_proof);
    
    Print_SplitLine('-'); 
    std::cout << "audit ends >>>" << std::endl; 
    Print_SplitLine('-');


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



