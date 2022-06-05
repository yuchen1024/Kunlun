/*
** Modified from the following two projects
** 1. https://github.com/emp-toolkit/
** 2. https://github.com/google/private-join-and-compute
*/

#ifndef KUNLUN_EC_POINT_HPP_
#define KUNLUN_EC_POINT_HPP_

#include "bigint.hpp"
#include "ec_group.hpp"
#include "global.hpp"
#include "aes.hpp"
#include "../utility/murmurhash2.hpp"
#include "../utility/routines.hpp"


// enable compressed representation of EC Point
//#define ECPOINT_COMPRESSED 


class BigInt;

// C++ Wrapper class for openssl EC_POINT.
class ECPoint {
public:
    EC_POINT* point_ptr; 
    
    // constructor functions
    
    ECPoint(); 
    ECPoint(const ECPoint& other);
    ECPoint(const EC_POINT* &other);
    
    // Creates an ECPoint object with given x, y affine coordinates.
    ECPoint(const BigInt& x, const BigInt& y);

    /* 
    ** Re-initialization function
    ** this function is somewhat dirty, only used as a ad-hoc bypass to initialize 
    ** global ECPoint object before group is created
    */

    void ReInitialize(); 
    // Returns an ECPoint that is a copy of this.
    void Clone(const ECPoint& other) const;

    void SetInfinity(); 

    // EC point group operations
    
    // Returns an ECPoint whose value is (this * scalar).
    ECPoint Mul(const BigInt& scalar) const;

    // Returns an ECPoint whose value is (this + other).
    ECPoint Add(const ECPoint& other) const;

    // Returns an ECPoint whose value is (- this), the additive inverse of this.
    ECPoint Invert() const;

    // Returns an ECPoint whose value is (this - other).
    ECPoint Sub(const ECPoint& other) const; 


    // attribute check operations

    // Returns "true" if the value of this ECPoint is the point-at-infinity.
    // (The point-at-infinity is the additive unit in the EC group).
    bool IsOnCurve() const; 
    bool IsValid() const;
    bool IsAtInfinity() const;  

    // Returns true if this equals point, false otherwise.
    bool CompareTo(const ECPoint& point) const;
    bool ThreadSafeCompareTo(const ECPoint& point) const;


    inline ECPoint& operator=(const ECPoint& other) { EC_POINT_copy(this->point_ptr, other.point_ptr); return *this; }

    inline bool operator==(const ECPoint& other) const{ return this->CompareTo(other); }

    inline bool operator!=(const ECPoint& other) const{ return !this->CompareTo(other);}

    inline ECPoint operator-() const { return this->Invert(); }

    inline ECPoint operator+(const ECPoint& other) const { return this->Add(other); }

    inline ECPoint operator*(const BigInt& scalar) const { return this->Mul(scalar); }

    inline ECPoint operator-(const ECPoint& other) const { return this->Sub(other); }

    inline ECPoint& operator+=(const ECPoint& other) { return *this = *this + other; }

    inline ECPoint& operator*=(const BigInt& scalar) { return *this = *this * scalar; }

    inline ECPoint& operator-=(const ECPoint& other) { return *this = *this - other; }

    void Print() const;

    void Print(std::string note) const;  

    std::string ToByteString() const;
    std::string ThreadSafeToByteString() const; 
    std::string ToHexString() const;

    size_t ToUint64() const; 
    size_t FastToUint64() const; 

    friend std::ofstream &operator<<(std::ofstream &fout, const ECPoint &A); 
 
    friend std::ifstream &operator>>(std::ifstream &fin, ECPoint &A);
};

// const static BigInt bn_order(order);  

ECPoint::ECPoint(){
    this->point_ptr = EC_POINT_new(group);
}

ECPoint::ECPoint(const ECPoint& other){
    this->point_ptr = EC_POINT_new(group);
    EC_POINT_copy(this->point_ptr, other.point_ptr);
}

ECPoint::ECPoint(const EC_POINT* &other){
    this->point_ptr = EC_POINT_new(group);
    EC_POINT_copy(this->point_ptr, other);
}

ECPoint::ECPoint(const BigInt& x, const BigInt& y){
    this->point_ptr = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates_GFp(group, this->point_ptr, x.bn_ptr, y.bn_ptr, bn_ctx);
}

void ECPoint::ReInitialize(){
    if (this->point_ptr == nullptr){
        this->point_ptr = EC_POINT_new(group);
    }
}

// dirty but thread safe implementation by setting bn_ctx = nullptr 
ECPoint ECPoint::Mul(const BigInt& scalar) const {
    ECPoint result; 
    // use fix-point exp with precomputation
    if (EC_POINT_cmp(group, this->point_ptr, generator, ec_ctx) == 0){
        CRYPTO_CHECK(1 == EC_POINT_mul(group, result.point_ptr, scalar.bn_ptr, nullptr, nullptr, ec_ctx));
    }
    else{
        CRYPTO_CHECK(1 == EC_POINT_mul(group, result.point_ptr, nullptr, this->point_ptr, scalar.bn_ptr, ec_ctx));
    }
 
    return result;
}


ECPoint ECPoint::Add(const ECPoint& other) const {  

    ECPoint result; 
    CRYPTO_CHECK(1 == EC_POINT_add(group, result.point_ptr, this->point_ptr, other.point_ptr, ec_ctx)); 
    return result; 
}


ECPoint ECPoint::Invert() const {
    // Create a copy of this.
    ECPoint result = (*this);  
    CRYPTO_CHECK(1 == EC_POINT_invert(group, result.point_ptr, ec_ctx)); 
    return result; 
}


ECPoint ECPoint::Sub(const ECPoint& other) const { 
    ECPoint result = other.Invert(); 
    CRYPTO_CHECK(1 == EC_POINT_add(group, result.point_ptr, this->point_ptr, result.point_ptr, ec_ctx));
    return result; 
}


void ECPoint::Clone(const ECPoint& other) const {
    CRYPTO_CHECK(1 == EC_POINT_copy(this->point_ptr, other.point_ptr)); 
}


bool ECPoint::IsAtInfinity() const {
    return EC_POINT_is_at_infinity(group, this->point_ptr);
}

// Returns true if the given point is in the group.
bool ECPoint::IsOnCurve() const {
    return (1 == EC_POINT_is_on_curve(group, this->point_ptr, bn_ctx));
}

// Checks if the given point is valid. Returns false if the point is not in the group or if it is the point is at infinity.
bool ECPoint::IsValid() const{
    if (!this->IsOnCurve() || this->IsAtInfinity()){
        return false;
    }
    return true;
}

bool ECPoint::CompareTo(const ECPoint& other) const{
    return (0 == EC_POINT_cmp(group, this->point_ptr, other.point_ptr, ec_ctx));
}


void ECPoint::SetInfinity()
{
    CRYPTO_CHECK(1 == EC_POINT_set_to_infinity(group, this->point_ptr));
}

void ECPoint::Print() const
{ 
    char *ecp_str = EC_POINT_point2hex(group, this->point_ptr, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
    std::cout << ecp_str << std::endl; 
    OPENSSL_free(ecp_str); 
}

// print an EC point with note
void ECPoint::Print(std::string note) const
{ 
    std::cout << note << " = "; 
    this->Print(); 
}


std::string ECPoint::ToByteString() const
{
    std::string ecp_str(POINT_COMPRESSED_BYTE_LEN, '0'); 

    EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, 
                       reinterpret_cast<unsigned char *>(&ecp_str[0]), POINT_COMPRESSED_BYTE_LEN, ec_ctx);
    return ecp_str; 
}

// std::string ECPoint::ThreadSafeToByteString() const
// {
//     std::string ecp_str(POINT_COMPRESSED_BYTE_LEN, '0');   
//     EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, 
//                        reinterpret_cast<unsigned char *>(&ecp_str[0]), POINT_COMPRESSED_BYTE_LEN, nullptr);
//     return ecp_str; 
// }

// make sure you have allocate enough memory for buffer
// does not make this check to efficiency concern
// inline void ECPoint::ThreadSafeToByteArray(unsigned char* buffer) const
// {
//     EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, nullptr); 
// }

/* convert an EC point to string */
std::string ECPoint::ToHexString() const
{
    std::stringstream ss; 
    ss << EC_POINT_point2hex(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, ec_ctx);
    return ss.str();  
}


size_t ECPoint::ToUint64() const
{
    // standard method
    unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
    memset(buffer, 0, POINT_COMPRESSED_BYTE_LEN); 
    EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, buffer, 
                       POINT_COMPRESSED_BYTE_LEN, ec_ctx);
    return MurmurHash64A(buffer, POINT_COMPRESSED_BYTE_LEN, fixed_salt); 
}

// adhoc lossy encoding for ECPoint based on AES
size_t ECPoint::FastToUint64() const 
{

    unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
    memset(buffer, 0, POINT_COMPRESSED_BYTE_LEN); 
    EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, buffer, 
                       POINT_COMPRESSED_BYTE_LEN, ec_ctx);

    block data[2];
    data[0] = _mm_load_si128((block *)(buffer));
    data[1] = _mm_load_si128((block *)(buffer+16));

    AES::FastECBEnc(fix_aes_enc_key, &data[0], 1);

    data[1] = _mm_xor_si128(data[1], data[0]);

    size_t hashvalue; 
    memcpy(&hashvalue, &data[1], 8); 

    return hashvalue; 
}



std::ofstream &operator<<(std::ofstream &fout, const ECPoint &A)
{ 
    unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_COMPRESSED_BYTE_LEN, ec_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_COMPRESSED_BYTE_LEN); 
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, ECPoint &A)
{ 
    unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
    fin.read(reinterpret_cast<char *>(buffer), POINT_COMPRESSED_BYTE_LEN); 
    EC_POINT_oct2point(group, A.point_ptr, buffer, POINT_COMPRESSED_BYTE_LEN, ec_ctx);
    return fin;            
}



/* 
 *  non-class functions
*/


std::ofstream &operator<<(std::ofstream &fout, const std::vector<ECPoint> &vec_A)
{ 
    for(auto i = 0; i < vec_A.size(); i++){
        fout << vec_A[i];
    }
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, std::vector<ECPoint> &vec_A)
{ 
    for(auto i = 0; i < vec_A.size(); i++){
        fin >> vec_A[i];
    }
    return fin;            
}

// Creates an ECPoint object with the given x, y affine coordinates.
ECPoint CreateECPoint(const BigInt& x, const BigInt& y)
{
    ECPoint ecp_result(x, y);
    if (!ecp_result.IsValid()) {
        std::cerr << "ECGroup::CreateECPoint(x,y) - The point is not valid." << std::endl;
        exit(EXIT_FAILURE);
    }
    return ecp_result;
}

ECPoint GenRandomGenerator()
{
    BigInt bn_order(order); 
    ECPoint result = ECPoint(generator) * GenRandomBigIntBetween(bn_1, bn_order);
    return result; 
}

// Creates an ECPoint which is the identity.
ECPoint GetPointAtInfinity(){
    ECPoint result;
    CRYPTO_CHECK(1 == EC_POINT_set_to_infinity(group, result.point_ptr));
    return result;
}


bool IsSquare(const BigInt& q) {
    return q.ModExp(BigInt(curve_params_q), BigInt(curve_params_p)).IsOne();
}


// ecpoint vector operations

// mul exp operations
ECPoint ECPointVectorMul(const std::vector<ECPoint> &vec_A, std::vector<BigInt> &vec_a){
    if (vec_A.size()!=vec_a.size()){
        std::cerr << "vector size does not match" << std::endl; 
        exit(EXIT_FAILURE);
    }
    ECPoint result; 
    size_t LEN = vec_A.size(); 
    CRYPTO_CHECK(1 == EC_POINTs_mul(group, result.point_ptr, nullptr, LEN, 
                 (const EC_POINT**)vec_A.data(), (const BIGNUM**)vec_a.data(), ec_ctx));
    return result; 
}

// mul exp operations
ECPoint ECPointVectorMul(const std::vector<ECPoint> &vec_A, std::vector<BigInt> &vec_a, size_t start_index, size_t end_index){
    std::vector<ECPoint> subvec_A(vec_A.begin()+start_index, vec_A.begin()+end_index);
    std::vector<BigInt>  subvec_a(vec_a.begin()+start_index, vec_a.begin()+end_index);
    return ECPointVectorMul(subvec_A, subvec_a); 
}


/* g[i] = g[i]+h[i] */ 
std::vector<ECPoint> ECPointVectorAdd(std::vector<ECPoint> &vec_A, std::vector<ECPoint> &vec_B)
{
    if (vec_A.size()!= vec_B.size()) {
        std::cerr << "vector size does not match!" << std::endl;
        exit(EXIT_FAILURE); 
    }
    size_t LEN = vec_A.size();
    std::vector<ECPoint> vec_result(LEN); 

    #pragma omp parallel for num_threads(thread_count)
    for (auto i = 0; i < vec_A.size(); i++) {
        vec_result[i] = vec_A[i] + vec_B[i]; 
    }
    return vec_result;
}


/* vec_result[i] = vec_A[i] * a */ 
inline std::vector<ECPoint> ECPointVectorScalar(std::vector<ECPoint> &vec_A, BigInt &a)
{
    size_t LEN = vec_A.size();
    std::vector<ECPoint> vec_result(LEN);  

    #pragma omp parallel for num_threads(thread_count)
    for (auto i = 0; i < LEN; i++) {
        vec_result[i] = vec_A[i] * a;  
    }
    return vec_result;  
}



/* result[i] = A[i]*a[i] */ 
inline std::vector<ECPoint> ECPointVectorProduct(const std::vector<ECPoint> &vec_A, std::vector<BigInt> &vec_a)
{
    if (vec_A.size() != vec_a.size()) {
        std::cerr << "vector size does not match!" << std::endl;
        exit(EXIT_FAILURE); 
    } 

    size_t LEN = vec_A.size(); 
    std::vector<ECPoint> vec_result(LEN);
    
    #pragma omp parallel for num_threads(thread_count)
    for (auto i = 0; i < LEN; i++) {
        vec_result[i] = vec_A[i] * vec_a[i];  
    } 
    return vec_result;  
}


/* generate a vector of random EC points */  
std::vector<ECPoint> GenRandomECPointVector(size_t LEN)
{
    std::vector<ECPoint> vec_result(LEN); 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < LEN; i++){ 
        vec_result[i] = GenRandomGenerator(); 
    }
    return vec_result;
}

ECPoint GenRandomECPoint()
{
    return GenRandomGenerator(); 
}

// print an EC Point vector
void PrintECPointVector(const std::vector<ECPoint> &vec_A, std::string note)
{ 
    for (auto i = 0; i < vec_A.size(); i++)
    {
        std::cout << note << "[" << i << "]="; 
        vec_A[i].Print(); 
    }
}

/* customized hash for ECPoint class */

class ECPointHash{
public:
    size_t operator()(const ECPoint& A) const
    {
        return std::hash<std::string>{}(A.ToByteString());
    }
};


auto ECPoint_Lexical_Compare = [](ECPoint A, ECPoint B){ 
    return A.ToByteString() < B.ToByteString(); 
};


#endif  // KUNLUN_EC_POINT_HPP_