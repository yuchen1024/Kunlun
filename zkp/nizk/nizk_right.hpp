/***********************************************************************************
this hpp implements many_out_of_many proof 
***********************************************************************************/
#ifndef MANY_OUT_OF_MANY_HPP_
#define MANY_OUT_OF_MANY_HPP_
#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../commitment/pedersen.hpp"
#include "../../utility/polymul.hpp"
#include <utility>
#include <iostream>


namespace ManyOutOfMany{
    
using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of ManyOutOfManyProof
struct PP
{
    size_t Com_LEN;
    size_t Log_Com_Len;
    Pedersen::PP com_part;
    ECPoint g;
   
};
std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout<<pp.Com_LEN<<pp.Log_Com_Len<<pp.com_part<<pp.g;
    return fout;
}
std::ifstream &operator>>(std::ifstream &fin, PP& pp)
{
    fin>>pp.Com_LEN>>pp.Log_Com_Len>>pp.com_part>>pp.g;
    return fin;  
}

struct Instance
{
    size_t Com_Num;
    //devide the cipher into two parts in order to compute efficient
    std::vector<ECPoint> vec_cipher_bal_left;
    std::vector<ECPoint> vec_cipher_bal_right;
    std::vector<ECPoint> vec_cipher_value;
    ECPoint cipher4D; //D is equal to g^r
    std::vector<ECPoint> vec_pk;
    ECPoint gepoch;
    ECPoint uepoch;
};
struct Witness
{
    size_t Ran_num;
    BigInt l0;
    BigInt l1;
    BigInt value;
    BigInt sk;
    BigInt r;
    BigInt vprime;
};
//this maybe a dirty way to implement the randoms reuse,if we combine the proof into one,we can avoid this
struct ConsRandom{
    BigInt kb;
    std::vector<BigInt> vec_al0;
    std::vector<BigInt> vec_al1;
};
// define structure of ManyOutOfManyProof
struct Proof
{
    size_t Num;// it is not necessary, but we can use it to check the number of the proof
    ECPoint proof_ComA, proof_ComB ;
    std::vector<ECPoint> vec_lower_cipher_bal_left;
    std::vector<ECPoint> vec_lower_cipher_bal_right;
    std::vector<ECPoint> vec_lower_cipher_value;
    std::vector<ECPoint> lower_cipher4D;
    std::vector<ECPoint> lower_vec_pk;
    std::vector<ECPoint> lower_vec_g;
    std::vector<ECPoint> lower_vec_oppcipher;
    std::vector<ECPoint> lower_vec_oppcipherpk;
    std::vector<BigInt> vec_proof_f0;
    std::vector<BigInt> vec_proof_f1;
    BigInt proof_Za;
    BigInt proof_Ssk, proof_Sr, proof_Sb0, proof_Sb1;
    ECPoint proof_Ay_re_enc, proof_AD_re_enc,proof_Ab0_re_enc,proof_Ab1_re_enc,proof_Ax_re_enc;
    ECPoint proof_Au;
 
};
std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout<<proof.Num<<proof.proof_ComA<<proof.proof_ComB;
    size_t m=proof.vec_lower_cipher_bal_left.size();
    for(auto i=0;i<m;i++)
    {
        fout<<proof.vec_lower_cipher_bal_left[i]
            <<proof.vec_lower_cipher_bal_right[i]
            <<proof.vec_lower_cipher_value[i]
            <<proof.lower_cipher4D[i]
            <<proof.lower_vec_pk[i]
            <<proof.lower_vec_g[i]
            <<proof.lower_vec_oppcipher[i]
            <<proof.lower_vec_oppcipherpk[i]
            <<proof.vec_proof_f0[i]
            <<proof.vec_proof_f1[i];
    }
    fout<<proof.proof_Ssk<<proof.proof_Sr
        <<proof.proof_Sb0<<proof.proof_Sb1;
    fout<<proof.proof_Ay_re_enc<<proof.proof_AD_re_enc
        <<proof.proof_Ab0_re_enc<<proof.proof_Ab1_re_enc
        <<proof.proof_Ax_re_enc<<proof.proof_Au; 

    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin>>proof.Num>>proof.proof_ComA>>proof.proof_ComB;
    size_t m=proof.vec_lower_cipher_bal_left.size();
    for(auto i=0;i<m;i++)
    {
        fin>>proof.vec_lower_cipher_bal_left[i]
            >>proof.vec_lower_cipher_bal_right[i]
            >>proof.vec_lower_cipher_value[i]
            >>proof.lower_cipher4D[i]
            >>proof.lower_vec_pk[i]
            >>proof.lower_vec_g[i]
            >>proof.lower_vec_oppcipher[i]
            >>proof.lower_vec_oppcipherpk[i]
            >>proof.vec_proof_f0[i]
            >>proof.vec_proof_f1[i];
    }
    fin>>proof.proof_Ssk>>proof.proof_Sr
        >>proof.proof_Sb0>>proof.proof_Sb1;
    fin>>proof.proof_Ay_re_enc>>proof.proof_AD_re_enc
        >>proof.proof_Ab0_re_enc>>proof.proof_Ab1_re_enc
        >>proof.proof_Ax_re_enc>>proof.proof_Au;
    return fin; 
}
void PrintProof(Proof &proof)
{
    std::cout<<"Num:"<<proof.Num<<std::endl;
    proof.proof_ComA.Print("proof_ComA");
    proof.proof_ComB.Print("proof_ComB");
    size_t m=proof.vec_lower_cipher_bal_left.size();
    for(auto i=0;i<m;i++)
    {
        proof.vec_lower_cipher_bal_left[i].Print("vec_lower_cipher_bal_left");
        proof.vec_lower_cipher_bal_right[i].Print("vec_lower_cipher_bal_right");
        proof.vec_lower_cipher_value[i].Print("vec_lower_cipher_value");
        proof.lower_cipher4D[i].Print("lower_cipher4D");
        proof.lower_vec_pk[i].Print("lower_vec_pk");
        proof.lower_vec_g[i].Print("lower_vec_g");
        proof.lower_vec_oppcipher[i].Print("lower_vec_oppcipher");
        proof.lower_vec_oppcipherpk[i].Print("lower_vec_oppcipherpk");
        proof.vec_proof_f0[i].Print("vec_proof_f0");
        proof.vec_proof_f1[i].Print("vec_proof_f1");
    }
    proof.proof_Ssk.Print("proof_Ssk");
    proof.proof_Sr.Print("proof_Sr");
    proof.proof_Sb0.Print("proof_Sb0");
    proof.proof_Sb1.Print("proof_Sb1");

    proof.proof_Ay_re_enc.Print("proof_Ay_re_enc");
    proof.proof_AD_re_enc.Print("proof_AD_re_enc");
    proof.proof_Ab0_re_enc.Print("proof_Ab0_re_enc");
    proof.proof_Ab1_re_enc.Print("proof_Ab1_re_enc");
    proof.proof_Ax_re_enc.Print("proof_Ax_re_enc");
    proof.proof_Au.Print("proof_Au");
}

PP Setup(size_t Com_LEN, size_t Log_Com_Len,Pedersen::PP &com_part)
{

    PP pp;
    pp.Com_LEN = Com_LEN;
    pp.Log_Com_Len = Log_Com_Len;
    pp.com_part = com_part;
    pp.g = ECPoint(generator); 
    return pp;
}

// multiplicate the element of the vector
BigInt Accumulate(std::vector<BigInt> vec,const BigInt &mod)
{
    BigInt ans=BigInt(bn_1);
    for(auto i=0;i<vec.size();i++)
    {
        ans=(ans*vec[i])%mod;
    }
    return ans;
}
// generate the Polynomial of index i
std::vector<BigInt> BigIntPolModProduct(std::vector< std::vector<std::pair<BigInt, BigInt>> >vec_F,BigInt index, BigInt mod)
{
    size_t k=vec_F.size(); // n is the number of rows, m is the number of columns,m=2;
    size_t m=vec_F[0].size();
    std::vector<BigInt> vec_ans(k+1,bn_0);
    size_t n=1<<k; // n=2^k;
    size_t sum=0;
    std::vector<BigInt> vec_tmp(k);
    for(auto i=0;i<n;i++)
    {
        for(auto j=0;j<k;j++)
        {
            if(((i>>j)&1)==1)
            {
                sum++;
                vec_tmp[j]=vec_F[j][index.GetTheNthBit(j)].first;
            }
            else
            {
                vec_tmp[j]=vec_F[j][index.GetTheNthBit(j)].second;
            }

        }
        BigInt tmp_acc=Accumulate(vec_tmp,mod);
        vec_ans[sum]=(vec_ans[sum]+tmp_acc)%mod;
        sum=0;      
    }
    return vec_ans;
}
/* generate a^n = (a^0, a^1, a^2, ..., a^{n-1}) */ 
std::vector<BigInt> GenBigIntPowerVector(size_t LEN, const BigInt &a)
{
    
    std::vector<BigInt> vec_result(LEN);
    vec_result[0] = BigInt(bn_1); 
    for (auto i = 1; i < LEN; i++)
    {
        vec_result[i] = (vec_result[i-1] * a) % order; // result[i] = result[i-1]*a % order
    }
    return vec_result; 
}
/* generate a^n = (a^0,a^0, a^1, a^2, ..., a^{n-2}) */
std::vector<BigInt> GenBigIntPowerVector4sdpt(size_t LEN, const BigInt &a)
{
    
    std::vector<BigInt> vec_result(LEN);
    vec_result[0] = BigInt(bn_1);
    vec_result[1] = BigInt(bn_1); 
    for (auto i = 2; i < LEN; i++)
    {
        vec_result[i] = (vec_result[i-1] * a) % order; // result[i] = result[i-1]*a % order
    }
    return vec_result; 
}

// circularly shifts the vector v of field elements by the integer j, choose right shift 
std::vector<BigInt> Shift(std::vector<BigInt> vec, size_t j)
{
    size_t n = vec.size(); 
    std::vector<BigInt> vec_result(n); 
    for (size_t i = 0; i < n; i++)
    {
        vec_result[i] = vec[(i+j)%n]; 
    }
    return vec_result; 
}

// transposit the matrix
std::vector<std::vector<BigInt>> BigIntMatrixtransposition(std::vector<std::vector<BigInt>> vec)
{
    size_t n=vec.size();
    size_t m=vec[0].size();
    std::vector<std::vector<BigInt>> vec_result(m,std::vector<BigInt>(n));
    for(auto i=0;i<n;i++)
    {
        for(auto j=0;j<m;j++)
        {
            vec_result[j][i]=vec[i][j];
        }
    }
    return vec_result;
}
// get the nth bit of element
size_t GetTheNthBit(size_t index, size_t n)
{
    return (index>>n)&1;
}

//prove the sender encrypt value is -v, receiver encrypt value is v, the index of them is opposite
void Prove(PP &pp,Witness &witness,Instance &instance,std::string &transcript_str, Proof &proof,ConsRandom &cons_random)
{

    BigInt ra = GenRandomBigIntLessThan(order); 
    BigInt rb = GenRandomBigIntLessThan(order);
    BigInt rc = GenRandomBigIntLessThan(order);
    BigInt rd = GenRandomBigIntLessThan(order);
    size_t n=pp.Com_LEN;
    size_t m=pp.Log_Com_Len;
    proof.Num=n;
    std::vector<BigInt> al0(m);
    std::vector<BigInt> bl0(m);
    std::vector<BigInt> al1(m);
    std::vector<BigInt> bl1(m);
    BigInt l0=witness.l0;
    BigInt l1=witness.l1;

    size_t l0_size_t=l0.ToUint64();
    size_t l1_size_t=l1.ToUint64();
    
    for(auto i=0; i<m; i++)
    {
        al0[i]=GenRandomBigIntLessThan(order);
        al1[i]=GenRandomBigIntLessThan(order);
        if(l0.GetTheNthBit(i)==1)   
        {
            bl0[i]=bn_1;
        }
        else
        {
            bl0[i]=bn_0;
        }
        if(l1.GetTheNthBit(i)==1)   
        {
            bl1[i]=bn_1;
        }
        else
        {
            bl1[i]=bn_0;
        }
    }
    cons_random.vec_al0=al0;
    cons_random.vec_al1=al1;
    std::vector<BigInt> vec_ma0(2*m);
    std::vector<BigInt> vec_mb0(2*m);
    std::vector<BigInt> vec_ma1(2*m);
    std::vector<BigInt> vec_mb1(2*m);
    std::vector<BigInt> vec_ma(4*m+2);
    std::vector<BigInt> vec_mb(4*m+2);

    /*fill vec_ma0 and vec_mb0,the first part*/
    std::copy(al0.begin(), al0.end(), vec_ma0.begin());
    std::copy(al1.begin(), al1.end(), vec_ma0.begin()+m);
    std::copy(bl0.begin(), bl0.end(), vec_mb0.begin());
    std::copy(bl1.begin(), bl1.end(), vec_mb0.begin()+m);

    /*fill vec_ma1*/
    std::vector<BigInt> vec_tmpa(m);
    BigInt modx=order;
    vec_tmpa=BigIntVectorModNegate(al0,modx);
  
    vec_tmpa=BigIntVectorModProduct(vec_tmpa, al0, order);
    std::copy(vec_tmpa.begin(), vec_tmpa.end(), vec_ma1.begin());

    vec_tmpa=BigIntVectorModNegate(al1,modx);
    vec_tmpa=BigIntVectorModProduct(vec_tmpa, al1, order);
    std::copy(vec_tmpa.begin(), vec_tmpa.end(), vec_ma1.begin()+m);

    /*fill vec_mb1*/
    std::vector<BigInt> vec_tmpb(m);
    BigInt bk2=bn_2.Negate();
    std::vector<BigInt> bn1(m,bn_1);
    vec_tmpb=BigIntVectorModScalar(bl0, bk2, order);
 
    vec_tmpb=BigIntVectorModAdd(vec_tmpb, bn1, order);
    //vec_tmpb=BigIntVectorModSub(bn1,vec_tmpb, order);
    vec_tmpb=BigIntVectorModProduct(vec_tmpb, al0, order);

    std::copy(vec_tmpb.begin(), vec_tmpb.end(), vec_mb1.begin());

    vec_tmpb=BigIntVectorModScalar(bl1, bk2, order);
 
    vec_tmpb=BigIntVectorModAdd(vec_tmpb, bn1, order);
    //vec_tmpb=BigIntVectorModSub(bn1, vec_tmpb,order);
    vec_tmpb=BigIntVectorModProduct(vec_tmpb, al1, order);
    std::copy(vec_tmpb.begin(), vec_tmpb.end(), vec_mb1.begin()+m);

    /*fill vec_ma and vec_mb*/
    std::copy(vec_ma0.begin(), vec_ma0.end(), vec_ma.begin());
    std::copy(vec_ma1.begin(), vec_ma1.end(), vec_ma.begin()+2*m);
    std::copy(vec_mb0.begin(), vec_mb0.end(), vec_mb.begin());
    std::copy(vec_mb1.begin(), vec_mb1.end(), vec_mb.begin()+2*m);

    vec_ma[4*m]=vec_ma[0]*vec_ma[m]%order;
    vec_ma[4*m+1]=vec_ma[4*m];
    if(vec_mb[0]==bn_1)
    {
        vec_mb[4*m]=vec_ma[m];
       
    }
    else
    {
        vec_mb[4*m]=vec_ma[0];
    }
    if(vec_mb[m]==bn_1)
    {
        vec_mb[4*m+1]=-vec_ma[m];
    }
    else
    {
        vec_mb[4*m+1]=-vec_ma[0];
    }
    
    proof.proof_ComA=Pedersen::Commit(pp.com_part, vec_ma, ra); //comiitment of A

    proof.proof_ComB=Pedersen::Commit(pp.com_part, vec_mb, rb); //commitment of B


    std::vector< std::vector< std::pair<BigInt, BigInt>> > vec_F0(m,std::vector<std::pair<BigInt, BigInt>>(2));
    std::vector< std::vector< std::pair<BigInt, BigInt>> > vec_F1(m,std::vector<std::pair<BigInt, BigInt>>(2)); 
  
    std::vector< std::vector<BigInt> > vec_P0(n,std::vector<BigInt>(m)); //n rows ,m columns
    std::vector< std::vector<BigInt> > vec_P1(n,std::vector<BigInt>(m)); //n rows ,m columns
    std::vector< std::vector<BigInt> > vec_P0transposition; //n rows ,m columns
    std::vector< std::vector<BigInt> > vec_P1transposition; //n rows ,m columns

    /*compute F and P*/
    for(auto k=0;k<m;k++)
    {   
        std::pair<BigInt, BigInt> tmp_F0;
        std::pair<BigInt, BigInt> tmp_F1;
        tmp_F0.first=bl0[k];
        tmp_F0.second=al0[k];
        vec_F0[k][1]=tmp_F0;
        tmp_F0.first=(bn_1-bl0[k]);
        tmp_F0.second=-al0[k];
        vec_F0[k][0]=tmp_F0;

        tmp_F1.first=bl1[k];
        tmp_F1.second=al1[k];
        vec_F1[k][1]=tmp_F1;
        tmp_F1.first=(bn_1-bl1[k]);
        tmp_F1.second=-al1[k];
        vec_F1[k][0]=tmp_F1;
    }

    std::vector<BigInt> vec_product_tmp;
    for(auto i=0;i<n;i++)
    {
        vec_product_tmp=BigIntPolModProduct(vec_F0,i, order);
        vec_P0[i]=vec_product_tmp; 
        vec_product_tmp=BigIntPolModProduct(vec_F1,i, order);
        vec_P1[i]=vec_product_tmp;            
    }
   
    vec_P0transposition=BigIntMatrixtransposition(vec_P0);
    vec_P1transposition=BigIntMatrixtransposition(vec_P1);

    /*compute challenge v*/
    transcript_str+=proof.proof_ComA.ToByteString();
    transcript_str+=proof.proof_ComB.ToByteString();
   

    BigInt v=Hash::StringToBigInt(transcript_str);

    size_t rs=witness.Ran_num; //rs should be equal to N;
   
    std::vector<BigInt> vec_ksi=GenBigIntPowerVector4sdpt(rs, v);

    //sample phi,chi_k,psi_k,omega from Zq
    std::vector<BigInt>phi(m);
    std::vector<BigInt>chi(m);
    std::vector<BigInt>psi(m);
    std::vector<BigInt>omega(m);

    for(auto i=0;i<m;i++)
    {
        phi[i]=GenRandomBigIntLessThan(order);
        chi[i]=GenRandomBigIntLessThan(order);
        psi[i]=GenRandomBigIntLessThan(order);
        omega[i]=GenRandomBigIntLessThan(order);
    }

    //compute the lower-order terms 
    std::vector<ECPoint> vec_lower_cipher_bal_left(m);
    std::vector<ECPoint> vec_lower_cipher_bal_right(m);
    std::vector<ECPoint> vec_lower_cipher_value(m);
    std::vector<ECPoint> lower_cipher4D(m);
    std::vector<ECPoint> lower_vec_pk(m);
    std::vector<ECPoint> lower_vec_g(m);
    std::vector<ECPoint> lower_vec_oppcipher(m);
    std::vector<ECPoint> lower_vec_oppcipherpk(m);
    
    //in this way, ECPointVectorMul is equal to MultiExp of the paper Anonymous Zehter
    ECPoint Ec_tmp;
    ECPoint Ec_tmpsum;
    
    for(size_t k=0;k<m;k++)
    {
        vec_lower_cipher_bal_left[k]=ECPointVectorMul(instance.vec_cipher_bal_left, vec_P0transposition[k]) + (instance.vec_pk[l0_size_t] * phi[k]);
        vec_lower_cipher_bal_right[k]=ECPointVectorMul(instance.vec_cipher_bal_right, vec_P0transposition[k]) + (pp.g * phi[k]);
        vec_lower_cipher_value[k]=ECPointVectorMul(instance.vec_cipher_value, vec_P0transposition[k]) + (instance.vec_pk[l0_size_t] * chi[k]);
        lower_cipher4D[k]=(pp.g * chi[k]);
        lower_vec_pk[k]=ECPointVectorMul(instance.vec_pk,vec_P0transposition[k])+ (instance.vec_pk[l0_size_t] * psi[k]);
        lower_vec_g[k]=pp.g * psi[k];
        lower_vec_oppcipherpk[k]=(pp.g * omega[k]);
        Ec_tmpsum.SetInfinity();
        //use the other way is also ok,but need to two vector addtionly 
        for(size_t l=0;l<2;l++)
        {
            for(size_t j=0;j<n/2;j++)
            {
                size_t index_ka=(2*j+l)%n;
                size_t index_Pl0=(l0_size_t+2*j)%n;
                size_t index_Pl1=(l1_size_t+2*j)%n;
                if(l==0)
                {
                    BigInt expont=witness.value * (-vec_P0[index_Pl0][k]+vec_P0[index_Pl1][k]);
                    Ec_tmp=pp.g*expont;
                }
                else
                {
                    BigInt expont=witness.value * (-vec_P1[index_Pl0][k]+vec_P1[index_Pl1][k]);
                    Ec_tmp=pp.g*expont;
                }
                Ec_tmpsum=Ec_tmpsum + Ec_tmp*vec_ksi[index_ka];                
            }
        }
        lower_vec_oppcipher[k]=Ec_tmpsum+(instance.cipher4D * omega[k]);
    }
    proof.vec_lower_cipher_bal_left=vec_lower_cipher_bal_left;
    proof.vec_lower_cipher_bal_right=vec_lower_cipher_bal_right;
    proof.vec_lower_cipher_value=vec_lower_cipher_value;
    proof.lower_cipher4D=lower_cipher4D;
    proof.lower_vec_pk=lower_vec_pk;
    proof.lower_vec_g=lower_vec_g;
    proof.lower_vec_oppcipher=lower_vec_oppcipher;
    proof.lower_vec_oppcipherpk=lower_vec_oppcipherpk;

    /*compute the challenge w*/
    //we use the parallel way to compute the challenge w, which is more efficient,if need,serial way is also ok 
    for(size_t i=0;i < m;i++)
    {
        transcript_str+=proof.vec_lower_cipher_bal_left[i].ToByteString();
        transcript_str+=proof.vec_lower_cipher_bal_right[i].ToByteString();
        transcript_str+=proof.vec_lower_cipher_value[i].ToByteString();
        transcript_str+=proof.lower_cipher4D[i].ToByteString();
        transcript_str+=proof.lower_vec_pk[i].ToByteString();
        transcript_str+=proof.lower_vec_g[i].ToByteString();
        transcript_str+=proof.lower_vec_oppcipher[i].ToByteString();
        transcript_str+=proof.lower_vec_oppcipherpk[i].ToByteString();
    }

    BigInt w=Hash::StringToBigInt(transcript_str);
    
    proof.vec_proof_f0.resize(m);
    proof.vec_proof_f1.resize(m);
    for(auto k=0;k<m;k++)
    {
        proof.vec_proof_f0[k]=(bl0[k]*w%order+al0[k])%order;
        proof.vec_proof_f1[k]=(bl1[k]*w%order+al1[k])%order;
        transcript_str += proof.vec_proof_f0[k].ToByteString();
        transcript_str += proof.vec_proof_f1[k].ToByteString();
    }
    proof.proof_Za=(rb*w%order+ra)%order;
    
    transcript_str += proof.proof_Za.ToByteString();

    BigInt z=Hash::StringToBigInt(transcript_str);
    
    //prover ??????anticipates?????? certain re-encryptions
    BigInt wem=w.ModExp(m,order);
    ECPoint re_cipherrbalright=instance.vec_cipher_bal_right[l0_size_t]*wem ;
    BigInt w_exp_k;
    for(auto k=0;k<m;k++)
    {
        w_exp_k=w.ModExp(k,order);
        w_exp_k=w_exp_k.ModMul(-phi[k],order);
        re_cipherrbalright=re_cipherrbalright+pp.g*w_exp_k;
    }
    ECPoint re_cipher4D=instance.cipher4D*wem;
    BigInt w4g=bn_0;
    //we can also use the other way to compute 
    for(auto k=0;k<m;k++)
    {
        w_exp_k=w.ModExp(k,order);
        w4g=(w4g-chi[k]*w_exp_k)%order;      
    }
    re_cipher4D=re_cipher4D+pp.g*w4g;

    BigInt wv=bn_0;
    for(auto k=0;k<m;k++)
    {
        w_exp_k=w.ModExp(k,order);
        wv=(wv+psi[k]*w_exp_k)%order;      
    }
    wv=wem.ModSub(wv,order);
    ECPoint re_cipher4g=pp.g*wv; 

    //compute the P of eval of w
    std::vector<BigInt> vec_evalP0(n);
    std::vector<BigInt> vec_evalP1(n);

    /*the fisrt way*/
    BigInt tmp_sumP0=bn_0;
    BigInt tmp_sumP1=bn_0;
    for(auto i=0;i<n;i++)
    {
        tmp_sumP0=bn_0;
        tmp_sumP1=bn_0;
        for(auto j=0;j<m;j++)
        {
            tmp_sumP0=(tmp_sumP0+vec_P0[i][j]*w.ModExp(BigInt(j),order))%order;
            tmp_sumP1=(tmp_sumP1+vec_P1[i][j]*w.ModExp(BigInt(j),order))%order;
        }
        vec_evalP0[i]=tmp_sumP0;
        vec_evalP1[i]=tmp_sumP1;
    }
    /*the sender_index and receiver_index's poly order is m.not m-1,so had better to use the second way*/
    vec_evalP0[l0_size_t]=(vec_evalP0[l0_size_t]+w.ModExp(m,order))%order;
    vec_evalP1[l1_size_t]=(vec_evalP1[l1_size_t]+w.ModExp(m,order))%order;

    /*the second way*/
    /*BigInt tmp_sump0=bn_1;
    BigInt tmp_sump1=bn_1;
    for(auto i=0;i<n;i++)
    {
        tmp_sump0=bn_1;
        tmp_sump1=bn_1;
        for(auto k=0;k<m;k++)
        {
            if(GetTheNthBit(i,k)==1)
            {
                tmp_sump0=tmp_sump0*proof.vec_proof_f0[k]%order;
                tmp_sump1=tmp_sump1*proof.vec_proof_f1[k]%order;
            }
            else
            {
                tmp_sump0=tmp_sump0*(w-proof.vec_proof_f0[k])%order;
                tmp_sump1=tmp_sump1*(w-proof.vec_proof_f1[k])%order;
            } 
        }
        vec_evalP0[i]=tmp_sump0;
        vec_evalP1[i]=tmp_sump1; 
    }*/
    ECPoint re_oppcipher;
    re_oppcipher.SetInfinity();
    std::vector<BigInt> vec_shift;

    for(size_t l=0; l<2; l++)
    {
        ECPoint re_tmp;
        for(size_t j=0; j<n/2; j++)
        {
            size_t index_ka=(2*j+l)%n;
            if(l==0)
            {
                vec_shift=Shift(vec_evalP0,2*j);
                re_tmp=ECPointVectorMul(instance.vec_pk,vec_shift);
                
            }
            else
            {
                vec_shift=Shift(vec_evalP1,2*j);
                re_tmp=ECPointVectorMul(instance.vec_pk,vec_shift);
                
            }
            re_oppcipher=re_oppcipher+re_tmp*vec_ksi[index_ka];  
                         
        }
    }
    for(auto k=0;k<m;k++)
    {
        w_exp_k=w.ModExp(k,order);
        w_exp_k=w_exp_k.ModMul(-omega[k],order);
        re_oppcipher=re_oppcipher+pp.g*w_exp_k;
    }

    BigInt ksk,kr,kb,ktau;
    ksk=GenRandomBigIntLessThan(order);
    kr=GenRandomBigIntLessThan(order);
    kb=GenRandomBigIntLessThan(order);
    ktau=GenRandomBigIntLessThan(order);

    cons_random.kb=kb;

    proof.proof_Ay_re_enc=re_cipher4g*ksk;
    proof.proof_AD_re_enc=pp.g*kr;
    
    BigInt zsquare= z*z% order; 
    BigInt zcube= zsquare*z% order;
    proof.proof_Ab0_re_enc=pp.g*kb+((re_cipher4D)*(-zsquare))*ksk;
    proof.proof_Ab1_re_enc=pp.g*kb+((re_cipherrbalright)*(zcube))*ksk;

    proof.proof_Ax_re_enc=re_oppcipher*kr;
    proof.proof_Au=instance.gepoch*ksk;

    transcript_str+=proof.proof_Ay_re_enc.ToByteString();
    transcript_str+=proof.proof_AD_re_enc.ToByteString();
    transcript_str+=proof.proof_Ab0_re_enc.ToByteString();
    transcript_str+=proof.proof_Ab1_re_enc.ToByteString();
    transcript_str+=proof.proof_Ax_re_enc.ToByteString();
    transcript_str+=proof.proof_Au.ToByteString();
   
    BigInt c=Hash::StringToBigInt(transcript_str);

    BigInt wemc=wem*c%order;
    proof.proof_Ssk=(ksk+c*witness.sk)%order;
    proof.proof_Sr=(kr+c*witness.r)%order;
    proof.proof_Sb0=(kb+((wemc*witness.value)%order)*zsquare)%order;
    proof.proof_Sb1=(kb+((wemc*witness.vprime)%order)*zcube)%order;
    
    #ifdef DEBUG
        std::cout << "Many prove Succeeds >>>" << std::endl; 
    #endif
    
    std::cout<<"Many prove proof Success "<<std::endl;
    
}

bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    
    size_t n=pp.Com_LEN;
    size_t m=pp.Log_Com_Len;

    transcript_str = "";
    transcript_str += proof.proof_ComA.ToByteString();
    transcript_str += proof.proof_ComB.ToByteString();

    BigInt v=Hash::StringToBigInt(transcript_str);

    std::vector<BigInt> vec_p0(n);
    std::vector<BigInt> vec_p1(n);

    for(auto i=0;i<m;i++)
    {
        transcript_str+=proof.vec_lower_cipher_bal_left[i].ToByteString();
        transcript_str+=proof.vec_lower_cipher_bal_right[i].ToByteString();
        transcript_str+=proof.vec_lower_cipher_value[i].ToByteString();
        transcript_str+=proof.lower_cipher4D[i].ToByteString();
        transcript_str+=proof.lower_vec_pk[i].ToByteString();
        transcript_str+=proof.lower_vec_g[i].ToByteString();
        transcript_str+=proof.lower_vec_oppcipher[i].ToByteString();
        transcript_str+=proof.lower_vec_oppcipherpk[i].ToByteString();
    }

    BigInt w=Hash::StringToBigInt(transcript_str);
    
    BigInt tmp_p0=bn_1;
    for(auto i=0;i<n;i++)
    {
        tmp_p0=bn_1;
        for(auto k=0;k<m;k++)
        {
            if(GetTheNthBit(i,k)==1)
            {
                tmp_p0=tmp_p0*proof.vec_proof_f0[k]%order;        
            }
            else
            {
                tmp_p0=(tmp_p0*((w-proof.vec_proof_f0[k])%order)%order)%order;
            }
        }
        vec_p0[i]=tmp_p0%order;      
    }
    
    BigInt tmp_p1=bn_1;
    for(auto i=0;i<n;i++)
    {
        tmp_p1=bn_1;
        for(auto k=0;k<m;k++)
        {
            if(GetTheNthBit(i,k)==1)
            {
                tmp_p1=tmp_p1*proof.vec_proof_f1[k]%order;        
            }
            else
            {
                tmp_p1=tmp_p1*(w-proof.vec_proof_f1[k])%order;
            }
        }
        vec_p1[i]=tmp_p1%order;      
    }

    std::vector<BigInt> vec_mvf(4*m+2);
    std::cout<<"begin to fill the commitment terms"<<std::endl;
    std::vector<BigInt> vec_mvftmp4f0(m);
    for(auto i=0;i<m;i++)
    {
        vec_mvftmp4f0[i]=proof.vec_proof_f0[i]*((w-proof.vec_proof_f0[i]+order)%order)%order;
    }

    std::vector<BigInt> vec_mvftmp4f1(m);
    for(auto i=0;i<m;i++)
    {
        vec_mvftmp4f1[i]=proof.vec_proof_f1[i]*((w-proof.vec_proof_f1[i]+order)%order)%order;
    }
   
    std::copy(proof.vec_proof_f0.begin(), proof.vec_proof_f0.end(), vec_mvf.begin());
    std::copy(proof.vec_proof_f1.begin(), proof.vec_proof_f1.end(), vec_mvf.begin()+m);
    std::copy(vec_mvftmp4f0.begin(), vec_mvftmp4f0.end(), vec_mvf.begin()+2*m);
    std::copy(vec_mvftmp4f1.begin(), vec_mvftmp4f1.end(), vec_mvf.begin()+3*m);
    PrintSplitLine('-');
    std::cout<<"success fill the commitment terms"<<std::endl;
    vec_mvf[4*m]=vec_mvf[0]*vec_mvf[m]%order;
    vec_mvf[4*m+1]=(((w-vec_mvf[0])%order)*((w-vec_mvf[m])%order))%order;

    std::cout<<"begin to check"<<std::endl;
    //check 1 the commitment
    ECPoint ComLeft=proof.proof_ComA+proof.proof_ComB*w;
    ECPoint ComRight=Pedersen::Commit(pp.com_part, vec_mvf, proof.proof_Za);
    if(ComLeft!=ComRight)
    {
        std::cout<<"Commitment is wrong"<<std::endl;
        return false;
    }
    else{
        std::cout<<"Commitment is right"<<std::endl;
    }
    
    //begin comp of re-encryptions
    ECPoint re_cipherrballeft=ECPointVectorMul(instance.vec_cipher_bal_left, vec_p0);
    ECPoint re_cipherrbalright=ECPointVectorMul(instance.vec_cipher_bal_right, vec_p0);
    ECPoint re_ciphervalue=ECPointVectorMul(instance.vec_cipher_value, vec_p0);
    BigInt wem=w.ModExp(m,order);
    ECPoint re_cipher4D=instance.cipher4D*wem;
    ECPoint re_pk=ECPointVectorMul(instance.vec_pk, vec_p0);
    ECPoint re_cipher4g=pp.g*wem;

    BigInt w_exp_k;
    for(auto k=0;k<m;k++)
    {
        w_exp_k=w.ModExp(k,order);
        re_cipherrballeft=re_cipherrballeft+(proof.vec_lower_cipher_bal_left[k]*(-w_exp_k));
        re_cipherrbalright=re_cipherrbalright+(proof.vec_lower_cipher_bal_right[k]*(-w_exp_k));
        re_ciphervalue=re_ciphervalue+(proof.vec_lower_cipher_value[k]*(-w_exp_k));
        re_cipher4D=re_cipher4D+(proof.lower_cipher4D[k]*(-w_exp_k));
        re_pk=re_pk+(proof.lower_vec_pk[k]*(-w_exp_k));
        re_cipher4g=re_cipher4g+(proof.lower_vec_g[k]*(-w_exp_k));
    }

    std::vector<BigInt> vec_ksi=GenBigIntPowerVector4sdpt(n, v);

    ECPoint re_Cx;
    re_Cx.SetInfinity();
    ECPoint re_yx;
    re_yx.SetInfinity();

    std::vector<BigInt> vec_shift1;
    std::vector<BigInt> vec_shift2;
    for(size_t l=0;l<2;l++)
    {
        ECPoint re_tmp0;
        ECPoint re_tmp1;
        for(size_t j=0;j<n/2;j++)
        {
            size_t index_ka=(2*j+l)%n;
            if(l==0)
            {
                vec_shift1=Shift(vec_p0,2*j);
                re_tmp0=ECPointVectorMul(instance.vec_cipher_value,vec_shift1);
                re_tmp1=ECPointVectorMul(instance.vec_pk,vec_shift1);
            }
            else
            {
                vec_shift2=Shift(vec_p1,2*j);
                re_tmp0=ECPointVectorMul(instance.vec_cipher_value,vec_shift2);
                re_tmp1=ECPointVectorMul(instance.vec_pk,vec_shift2);
            }
            re_Cx=re_Cx+re_tmp0*vec_ksi[index_ka];
            re_yx=re_yx+re_tmp1*vec_ksi[index_ka];
        }
        
    }

    for(auto k=0;k<m;k++)
    {
        w_exp_k=w.ModExp(k,order);
        re_Cx=re_Cx+(proof.lower_vec_oppcipher[k]*(-w_exp_k));
        re_yx=re_yx+(proof.lower_vec_oppcipherpk[k]*(-w_exp_k));
    }
    
    //compute the challenge z
    for(auto k=0;k<m;k++)
    {
        transcript_str += proof.vec_proof_f0[k].ToByteString();
        transcript_str += proof.vec_proof_f1[k].ToByteString();
    }
    transcript_str += proof.proof_Za.ToByteString();

    BigInt z=Hash::StringToBigInt(transcript_str);
    BigInt zsquare= z*z% order; 
    BigInt zcube= zsquare*z% order;

    //compute the challenge c
    transcript_str+=proof.proof_Ay_re_enc.ToByteString();
    transcript_str+=proof.proof_AD_re_enc.ToByteString();
    transcript_str+=proof.proof_Ab0_re_enc.ToByteString();
    transcript_str+=proof.proof_Ab1_re_enc.ToByteString();
    transcript_str+=proof.proof_Ax_re_enc.ToByteString();
    transcript_str+=proof.proof_Au.ToByteString();
   
    BigInt c=Hash::StringToBigInt(transcript_str);

    //check Ay 
    bool Validity=true;
    ECPoint re_Ayreencright=re_cipher4g*(proof.proof_Ssk)+re_pk*(-c);
    
    if(re_Ayreencright!=proof.proof_Ay_re_enc){
        std::cout<<"Ay check is wrong "<<std::endl;
        Validity=false;
        
    }
    //check AD
    ECPoint re_ADreencright=pp.g*(proof.proof_Sr)+instance.cipher4D*(-c);
    if(re_ADreencright!=proof.proof_AD_re_enc){
        std::cout<<"AD check is wrong "<<std::endl;
        Validity=false;
       
    }
    //check Ab0
    ECPoint re_Ab0reencright=pp.g*(proof.proof_Sb0)+(re_cipher4D*(-zsquare))*(proof.proof_Ssk)+(re_ciphervalue*(-zsquare))*(-c);
    if(re_Ab0reencright!=proof.proof_Ab0_re_enc){
        std::cout<<"Ab0 check is wrong "<<std::endl;
        Validity=false;
        
    }
    //check Ab1
    ECPoint re_Ab1reencright=pp.g*(proof.proof_Sb1)+(re_cipherrbalright*(zcube))*(proof.proof_Ssk)+(re_cipherrballeft*(zcube))*(-c);
    if(re_Ab1reencright!=proof.proof_Ab1_re_enc){
        std::cout<<"Ab1 check is wrong "<<std::endl;
        Validity=false;
       
    }
    
    //check Ax
    ECPoint re_Axreencright=re_Cx*(-c)+re_yx*(proof.proof_Sr);
    if(re_Axreencright!=proof.proof_Ax_re_enc){
        std::cout<<"Ax check is wrong "<<std::endl;
        Validity=false;     
    }
     //check Au
    ECPoint re_Auright=instance.gepoch*(proof.proof_Ssk)+instance.uepoch*(-c);
    if(re_Auright!=proof.proof_Au){
        std::cout<<"Au check is wrong "<<std::endl;
        Validity=false;
       
    }

    #ifdef DEBUG
    if (Validity){ 
        std::cout<< " accepts >>>" << std::endl; 
    }
    else{
        std::cout<< " rejects >>>" << std::endl; 
    }
    #endif

    if (Validity){ 
        std::cout<< "proof of right encryption accepts >>>" << std::endl; 
    }
    else{
        std::cout<< "proof of right encryption rejects >>>" << std::endl; 
    }
    return Validity;

}

}
#endif