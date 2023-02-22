#ifndef COMMITMENT_HPP_
#define COMMITMENT_HPP_


namespace Pedersen{

// define PP of Com
struct PP
{
    ECPoint g; 
    std::vector<ECPoint> vec_h;  
    size_t N_max; 
};

/* Setup algorithm */ 
PP Setup(size_t N_max)
{ 
    PP pp;
    pp.N_max = N_max;
    pp.g = ECPoint(generator); 
    /* 
    ** warning: the following method is ad-hoc and insafe cause it is not transparent
    ** we left a secure hash to many points mapping as the future work   
    */
    pp.vec_h = GenRandomECPointVector(N_max); 
    return pp; 
}


ECPoint Commit(PP &pp, std::vector<BigInt>& vec_m, BigInt r)
{
    if(pp.N_max < vec_m.size()){
        std::cerr << "message size is less than pp size" << std::endl;
    }
    size_t LEN = vec_m.size();
    std::vector<ECPoint> subvec_h(pp.vec_h.begin(), pp.vec_h.begin() + LEN);
    ECPoint commitment = pp.g * r + ECPointVectorMul(subvec_h, vec_m);
    return commitment;   
}


}
# endif




