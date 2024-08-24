#include "../sdpt/sdpt.hpp"
#include "../crypto/setup.hpp"
// count the number of transaction
BigInt count=bn_0;
void Build_SDPT_Test_Enviroment(size_t ringnumber)
{
    PrintSplitLine('-'); 
    std::cout << "build test enviroment for SDPT >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "setup SDPT system" << std::endl; 
    // setup adcp system
    
    size_t LOG_MAXIMUM_COINS = 32;      
    //size_t MAX_RECEIVER_NUM = 7;
    size_t AnonySetSize = ringnumber;  

    SDPT::SP sp;
    SDPT::PP pp;

    std::tie(pp, sp) = SDPT::Setup(LOG_MAXIMUM_COINS, AnonySetSize); 

    SDPT::Initialize(pp);

    std::string SDPT_SP_Filename = "sdpt.sp"; 
    SDPT::SaveSP(sp, SDPT_SP_Filename); 

    std::string sdpt_PP_Filename = "sdpt.pp"; 
    SDPT::SavePP(pp, sdpt_PP_Filename); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");


    // create accounts for Alice and Bob and Tax
    std::cout << "generate 16 accounts" << std::endl; 
    PrintSplitLine('-'); 

    BigInt Alice_balance = BigInt(512); 
    SDPT::Account Acct_Alice = SDPT::CreateAccount(pp, "Alice", Alice_balance); 
    std::string Alice_Acct_FileName = "Alice.account"; 
    SDPT::SaveAccount(Acct_Alice, Alice_Acct_FileName); 

    BigInt Bob_balance = BigInt(256);
    SDPT::Account Acct_Bob = SDPT::CreateAccount(pp, "Bob", Bob_balance); 
    std::string Bob_Acct_FileName = "Bob.account"; 
    SDPT::SaveAccount(Acct_Bob, Bob_Acct_FileName); 

    BigInt Carl_balance = BigInt(128); 
    SDPT::Account Acct_Carl = SDPT::CreateAccount(pp, "Carl", Carl_balance); 
    std::string Carl_Acct_FileName = "Carl.account"; 
    SDPT::SaveAccount(Acct_Carl, Carl_Acct_FileName); 

    BigInt David_balance = BigInt(64);
    SDPT::Account Acct_David = SDPT::CreateAccount(pp, "David", David_balance);
    std::string David_Acct_FileName = "David.account";
    SDPT::SaveAccount(Acct_David, David_Acct_FileName);

    BigInt Eve_balance = BigInt(32);
    SDPT::Account Acct_Eve = SDPT::CreateAccount(pp, "Eve", Eve_balance);
    std::string Eve_Acct_FileName = "Eve.account";
    SDPT::SaveAccount(Acct_Eve, Eve_Acct_FileName);

    BigInt Frank_balance = BigInt(16);
    SDPT::Account Acct_Frank = SDPT::CreateAccount(pp, "Frank", Frank_balance);
    std::string Frank_Acct_FileName = "Frank.account";
    SDPT::SaveAccount(Acct_Frank, Frank_Acct_FileName);

    BigInt Grace_balance = BigInt(32);
    SDPT::Account Acct_Grace = SDPT::CreateAccount(pp, "Grace", Grace_balance);
    std::string Grace_Acct_FileName = "Grace.account";
    SDPT::SaveAccount(Acct_Grace, Grace_Acct_FileName);

    BigInt Henry_balance = BigInt(32);
    SDPT::Account Acct_Henry = SDPT::CreateAccount(pp, "Henry", Henry_balance);
    std::string Henry_Acct_FileName = "Henry.account";
    SDPT::SaveAccount(Acct_Henry, Henry_Acct_FileName);

    BigInt Ida_balance = BigInt(32);
    SDPT::Account Acct_Ida = SDPT::CreateAccount(pp, "Ida", Ida_balance);
    std::string Ida_Acct_FileName = "Ida.account";
    SDPT::SaveAccount(Acct_Ida, Ida_Acct_FileName);

    BigInt Jack_balance = BigInt(32);
    SDPT::Account Acct_Jack = SDPT::CreateAccount(pp, "Jack", Jack_balance);
    std::string Jack_Acct_FileName = "Jack.account";
    SDPT::SaveAccount(Acct_Jack, Jack_Acct_FileName);

    BigInt Kate_balance = BigInt(32);
    SDPT::Account Acct_Kate = SDPT::CreateAccount(pp, "Kate", Kate_balance);
    std::string Kate_Acct_FileName = "Kate.account";
    SDPT::SaveAccount(Acct_Kate, Kate_Acct_FileName);

    BigInt Leo_balance = BigInt(32);
    SDPT::Account Acct_Leo = SDPT::CreateAccount(pp, "Leo", Leo_balance);
    std::string Leo_Acct_FileName = "Leo.account";
    SDPT::SaveAccount(Acct_Leo, Leo_Acct_FileName);

    BigInt Mary_balance = BigInt(32);
    SDPT::Account Acct_Mary = SDPT::CreateAccount(pp, "Mary", Mary_balance);
    std::string Mary_Acct_FileName = "Mary.account";
    SDPT::SaveAccount(Acct_Mary, Mary_Acct_FileName);

    BigInt Nick_balance = BigInt(32);
    SDPT::Account Acct_Nick = SDPT::CreateAccount(pp, "Nick", Nick_balance);
    std::string Nick_Acct_FileName = "Nick.account";
    SDPT::SaveAccount(Acct_Nick, Nick_Acct_FileName);

    BigInt Olivia_balance = BigInt(32);
    SDPT::Account Acct_Olivia = SDPT::CreateAccount(pp, "Olivia", Olivia_balance);
    std::string Olivia_Acct_FileName = "Olivia.account";
    SDPT::SaveAccount(Acct_Olivia, Olivia_Acct_FileName);

    BigInt Paul_balance = BigInt(32);
    SDPT::Account Acct_Paul = SDPT::CreateAccount(pp, "Paul", Paul_balance);
    std::string Paul_Acct_FileName = "Paul.account";
    SDPT::SaveAccount(Acct_Paul, Paul_Acct_FileName);

    BigInt Tax_balance = bn_0; 
    SDPT::Account Acct_Tax = SDPT::CreateAccount(pp, "Tax", Tax_balance); 
    std::string Tax_Acct_FileName = "Tax.account"; 
    SDPT::SaveAccount(Acct_Tax, Tax_Acct_FileName); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");
} 

void Emulate_SDPT_System(size_t ringnumber)
{
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    
    SDPT::SP sp;  
    SDPT::FetchSP(sp, "sdpt.sp"); 

    SDPT::PP pp;  
    SDPT::FetchPP(pp, "sdpt.pp"); 
    SDPT::PrintPP(pp); 

    SDPT::Account Acct_Alice;  
    SDPT::FetchAccount(Acct_Alice, "Alice.account"); 
    //SDPT::PrintAccount(Acct_Alice); 

    SDPT::Account Acct_Bob;  
    SDPT::FetchAccount(Acct_Bob, "Bob.account"); 
    //SDPT::PrintAccount(Acct_Bob); 

    SDPT::Account Acct_Carl;  
    SDPT::FetchAccount(Acct_Carl, "Carl.account"); 
    //SDPT::PrintAccount(Acct_Carl); 

    SDPT::Account Acct_David;
    SDPT::FetchAccount(Acct_David, "David.account");
    //SDPT::PrintAccount(Acct_David);

    SDPT::Account Acct_Eve;
    SDPT::FetchAccount(Acct_Eve, "Eve.account");
    //SDPT::PrintAccount(Acct_Eve);

    SDPT::Account Acct_Frank;
    SDPT::FetchAccount(Acct_Frank, "Frank.account");
    //SDPT::PrintAccount(Acct_Frank);

    SDPT::Account Acct_Grace;
    SDPT::FetchAccount(Acct_Grace, "Grace.account");
    //SDPT::PrintAccount(Acct_Grace);

    SDPT::Account Acct_Henry;
    SDPT::FetchAccount(Acct_Henry, "Henry.account");
    //SDPT::PrintAccount(Acct_Henry);

    SDPT::Account Acct_Ida;
    SDPT::FetchAccount(Acct_Ida, "Ida.account");
    //SDPT::PrintAccount(Acct_Ida);

    SDPT::Account Acct_Jack;
    SDPT::FetchAccount(Acct_Jack, "Jack.account");
    //SDPT::PrintAccount(Acct_Jack);

    SDPT::Account Acct_Kate;
    SDPT::FetchAccount(Acct_Kate, "Kate.account");
    //SDPT::PrintAccount(Acct_Kate);

    SDPT::Account Acct_Leo;
    SDPT::FetchAccount(Acct_Leo, "Leo.account");
    //SDPT::PrintAccount(Acct_Leo);

    SDPT::Account Acct_Mary;
    SDPT::FetchAccount(Acct_Mary, "Mary.account");
    //SDPT::PrintAccount(Acct_Mary);

    SDPT::Account Acct_Nick;
    SDPT::FetchAccount(Acct_Nick, "Nick.account");
    //SDPT::PrintAccount(Acct_Nick);

    SDPT::Account Acct_Olivia;
    SDPT::FetchAccount(Acct_Olivia, "Olivia.account");
    //SDPT::PrintAccount(Acct_Olivia);

    SDPT::Account Acct_Paul;
    SDPT::FetchAccount(Acct_Paul, "Paul.account");
    //SDPT::PrintAccount(Acct_Paul);

    SDPT::Account Acct_Tax;  
    SDPT::FetchAccount(Acct_Tax, "Tax.account"); 
    //SDPT::PrintAccount(Acct_Tax); 


    std::cout << "begin to the test of 1-to-1 anonymous tx" << std::endl;
    PrintSplitLine('-'); 
    BigInt v;
    std::cout<<"case 1: 1st valid 1-to-1 anonymous tx"<<std::endl;
    v = BigInt(32);
    std::vector<SDPT::AnonSet> AnonSetList;
    std::cout << "Alice is going to transfer "<< BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl;
    
    //std::string namelist[9]={Acct_Alice,Acct_Bob,Acct_Carl,Acct_David,Acct_Eve,Acct_Frank,Acct_Grace,Acct_Henry,Acct_Tax};
    std::vector<SDPT::Account> Accountlist{Acct_Alice,Acct_Bob,Acct_Carl,Acct_David,
                                Acct_Eve,Acct_Frank,Acct_Grace,Acct_Henry,
                                Acct_Ida,Acct_Jack,Acct_Kate,Acct_Leo,Acct_Mary,
                                Acct_Nick,Acct_Olivia,Acct_Paul,Acct_Tax};
    size_t sender_acc_index=0;
    size_t receiver_acc_index=1;
    SDPT::AnonSet AnonSet;
    size_t num_account=std::min(ringnumber,Accountlist.size());
    for(auto i=0;i<num_account;i++)
    {
        AnonSet.identity=Accountlist[i].identity;
        AnonSet.pk=Accountlist[i].pk;
        AnonSet.balance_act=Accountlist[i].balance_ct;
        AnonSetList.push_back(AnonSet);
    }
    //create 32 accounts additioanlly
    size_t numadd_account=std::max(size_t(32),ringnumber);
    for(auto i=0;i<numadd_account;i++)
    {
        BigInt account_balance = BigInt(32); 
        SDPT::Account Acct = SDPT::CreateAccount(pp, "Account"+std::to_string(i), account_balance); 
        std::string Acct_FileName = "Account"+std::to_string(i)+".account"; 
        SDPT::SaveAccount(Acct, Acct_FileName); 
        Accountlist.push_back(Acct);
    }
    //we create 16 accounts by hand, the other account we name is by "Account"+ id
    for(auto i=17;i<ringnumber;i++)
    {
        AnonSet.identity=Accountlist[i].identity;
        AnonSet.pk=Accountlist[i].pk;
        AnonSet.balance_act=Accountlist[i].balance_ct;
        AnonSetList.push_back(AnonSet);
    }
    size_t n=AnonSetList.size();
    if(n%2!=0)
    {
       std::cout<<"the number of the transaction participant number is not even"<<std::endl;
       std::cout<<"wrong transaction participant number"<<std::endl;
    }
   
    //index type is size_t in order to find the index of the sender and receiver,in the proof,we use BigInt
    size_t senderindex;
    size_t receiverindex;
    if(n==2)
    {
        senderindex=0;
        receiverindex=1;
    }
    else{
        senderindex=SDPT::getranindex(n);
        receiverindex=SDPT::getranindex(n);
        if(senderindex%2==receiverindex%2){
            receiverindex=(receiverindex+1)%n;
        }
        if(senderindex!=sender_acc_index){
            std::swap(AnonSetList[senderindex],AnonSetList[sender_acc_index]);
        }
        if(receiverindex!=receiver_acc_index&&receiverindex!=sender_acc_index&&senderindex!=receiver_acc_index){
        std::swap(AnonSetList[receiverindex],AnonSetList[receiver_acc_index]);
        }
    }
    
    std::cout<<"senderindex:"<<senderindex<<std::endl;
    std::cout<<"receiverindex:"<<receiverindex<<std::endl;
    count=count+bn_1;   
    std::cout<<"CreateAnoyTransaction "<<std::endl;
    SDPT::StofAnoyTransaction1 AnoyTransaction1 = SDPT::CreateAnoyTransaction1(pp, Acct_Alice, 
                                                v,AnonSetList, Acct_Bob.pk, count,senderindex,receiverindex);
    
    
    SDPT::StofAnoyTransaction2 AnoyTransaction2 = SDPT::CreateAnoyTransaction2(pp, Acct_Alice, 
                                                v,AnonSetList, Acct_Bob.pk, count,senderindex,receiverindex);
    std::cout<<"begin to mine"<<std::endl;
    std::vector<SDPT::Account> AccountList_miner(ringnumber);
    std::copy(Accountlist.begin(),Accountlist.begin()+ringnumber,AccountList_miner.begin());
    if(senderindex!=sender_acc_index)
    {
        std::swap(AccountList_miner[senderindex],AccountList_miner[sender_acc_index]);
    }
    if(receiverindex!=receiver_acc_index)
    {
        std::swap(AccountList_miner[receiverindex],AccountList_miner[receiver_acc_index]);
    }
    std::cout<<"AccountList_miner.size():"<<AccountList_miner.size()<<std::endl;
    SDPT::Miner1(pp, AnoyTransaction1, AccountList_miner); 
    SDPT::Miner2(pp, AnoyTransaction2, AccountList_miner);
    PrintSplitLine('-');

    std::cout << "after 1st valid 1-to-1 anonymous tx >>>>>>" << std::endl; 
    PrintSplitLine('-'); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    std::cout << "supervision1 of 1-to-1 anonymous tx begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    SDPT::SuperviseAnoyTx1(sp, pp,AnoyTransaction1);  
    std::cout << "supervision1 of 1-to-1 anonymous tx ends >>>" << std::endl; 
    PrintSplitLine('-');

    std::cout << "press any key to continue >>>" << std::endl;
    system ("read");

    std::cout << "supervision2 of 1-to-1 anonymous tx begins >>>" << std::endl; 
    PrintSplitLine('-'); 
    SDPT::SuperviseAnoyTx2(sp, pp,AnoyTransaction2);  
    std::cout << "supervision2 of 1-to-1 anonymous tx ends >>>" << std::endl; 
    PrintSplitLine('-');

}



int main()
{
    CRYPTO_Initialize();  
    // the ringnumber = the participants in the transaction, now we support the maximum >=2, had better set the ringnumber= 2^n
    //we only test the maximum=64, if set ringnumber >64, maybe is is also ok
    size_t ringnumber=8;
    Build_SDPT_Test_Enviroment(ringnumber); 
    Emulate_SDPT_System(ringnumber);

    CRYPTO_Finalize(); 

    return 0; 
}



