#ifndef KUNLUN_EC_POINT_HPP_
#define KUNLUN_EC_POINT_HPP_


#include "std.inc"
#include "openssl.inc"
#include "ec_group.hpp"
#include "bigint.hpp"
#include "../common/routines.hpp"

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

    void Serialize(std::ofstream &fout); 

    void Deserialize(std::ifstream &fin);

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


ECPoint ECPoint::Mul(const BigInt& scalar) const {
    ECPoint ecp_result;
    // use fix-point exp with precomputation
    if (EC_POINT_cmp(group, this->point_ptr, generator, bn_ctx) == 0){
        EC_POINT_mul(group, ecp_result.point_ptr, scalar.bn_ptr, nullptr, nullptr, bn_ctx);    
    }
    else{
        if (1 != EC_POINT_mul(group, ecp_result.point_ptr, nullptr, this->point_ptr, scalar.bn_ptr, bn_ctx)) {
            std::cerr << "EC_POINT_mul failed:" << OpenSSLErrorString() << std::endl;
        }
    }
    return std::move(ecp_result);
}

ECPoint ECPoint::Add(const ECPoint& other) const {
    ECPoint ecp_result;
    if (1 != EC_POINT_add(group, ecp_result.point_ptr, this->point_ptr, other.point_ptr, bn_ctx)) {
        std::cerr << "EC_POINT_add failed:" << OpenSSLErrorString() << std::endl;
    }
    return std::move(ecp_result); 
}

ECPoint ECPoint::Invert() const {
    // Create a copy of this.
    ECPoint ecp_result = (*this);  
    if (1 != EC_POINT_invert(group, ecp_result.point_ptr, bn_ctx)) {
        std::cerr <<"EC_POINT_invert failed:" << OpenSSLErrorString() << std::endl;
    }
    return std::move(ecp_result); 
}

ECPoint ECPoint::Sub(const ECPoint& other) const { 
    ECPoint ecp_result = other.Invert(); 
    if (1 != EC_POINT_add(group, ecp_result.point_ptr, this->point_ptr, ecp_result.point_ptr, bn_ctx)) {
        std::cerr << "EC_POINT_sub failed:" << OpenSSLErrorString() << std::endl;
    }
    return std::move(ecp_result); 
}

void ECPoint::Clone(const ECPoint& other) const {
    if (1 != EC_POINT_copy(this->point_ptr, other.point_ptr)) {
        std::cerr << "EC_POINT_copy failed:" << OpenSSLErrorString() << std::endl;
    }
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
    return (0 == EC_POINT_cmp(group, this->point_ptr, other.point_ptr, bn_ctx));
}

/* 
 *  non-class functions
*/

// Creates an ECPoint object with the given x, y affine coordinates.
ECPoint CreateECPoint(const BigInt& x, const BigInt& y){
    ECPoint ecp_result(x, y);
    if (!ecp_result.IsValid()) {
        std::cerr << "ECGroup::CreateECPoint(x,y) - The point is not valid." << std::endl;
    }
    return std::move(ecp_result);
}

ECPoint GenRandomGenerator(){
    ECPoint ecp_result = ECPoint(generator); 
    BigInt bn_order(order); 
    ecp_result = ecp_result * GenRandomBigIntBetween(bn_1, bn_order);
    return std::move(ecp_result); 
}

// Creates an ECPoint which is the identity.
ECPoint GetPointAtInfinity(){
    ECPoint ecp_result;
    if (EC_POINT_set_to_infinity(group, ecp_result.point_ptr) != 1) {
        std::cerr << "ECGroup::GetPointAtInfinity() - Could not get point at infinity." << std::endl;
    }
    return std::move(ecp_result);
}

bool IsSquare(const BigInt& q) {
    return q.ModExp(BigInt(curve_params_q), BigInt(curve_params_p)).IsOne();
}

bool TryHashToPoint(BigInt x, ECPoint& point) 
{
    BigInt y_square = (x.Exp(bn_3) + BigInt(curve_params_a) * x + BigInt(curve_params_b)).Mod(BigInt(curve_params_p));

    if (IsSquare(y_square)){
        BigInt y = y_square.ModSquareRoot(curve_params_p);
        if (y.IsBitSet(0)){
            point = CreateECPoint(x, y.ModNegate(curve_params_p));
        }
        point = CreateECPoint(x, y);
        return true; 
    }
    return false; 
}

ECPoint HashToPoint(const std::string& input) 
{
    ECPoint ecp_result; 

    BigInt p = BigInt(curve_params_p); 
    BigInt x = HashToBigInt(input);

    x = x.Mod(p);    
    while (true) {
        if (TryHashToPoint(x, ecp_result)) break; 
        x = HashToBigInt(BigIntToByteString(x));
    }

    return std::move(ecp_result);
}

void ECPoint::SetInfinity()
{
    this->Clone(GetPointAtInfinity());    
}

void ECPoint::Print() const
{
    char *ecp_str = EC_POINT_point2hex(group, this->point_ptr, POINT_CONVERSION_UNCOMPRESSED, NULL);
    std::cout << ecp_str << std::endl; 
    OPENSSL_free(ecp_str); 
}

// print an EC point with note
void ECPoint::Print(std::string note) const
{ 
    std::cout << note << " = "; 
    this->Print(); 
}

void ECPoint::Serialize(std::ofstream &fout)
{
    unsigned char buffer[POINT_BYTE_LEN];
    EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_BYTE_LEN); 
}

void ECPoint::Deserialize(std::ifstream &fin)
{
    unsigned char buffer[POINT_BYTE_LEN];
    fin.read(reinterpret_cast<char *>(buffer), POINT_BYTE_LEN); 
    EC_POINT_oct2point(group, this->point_ptr, buffer, POINT_BYTE_LEN, bn_ctx);
}

std::string ECPointToByteString(const ECPoint &A)
{
    unsigned char buffer[POINT_BYTE_LEN]; 
    memset(buffer, 0, POINT_BYTE_LEN); 

    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, bn_ctx);
    std::string result; 
    result.assign(reinterpret_cast<char *>(buffer), POINT_BYTE_LEN);

    return std::move(result); 
}

/* convert an EC point to string */
std::string ECPointToHexString(const ECPoint &A)
{
    std::stringstream ss; 
    ss << EC_POINT_point2hex(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, bn_ctx);
    return ss.str();  
}


std::ofstream &operator<<(std::ofstream &fout, const ECPoint &A)
{ 
    unsigned char buffer[POINT_BYTE_LEN];
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, BN_BYTE_LEN+1, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_BYTE_LEN); 
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, ECPoint &A)
{ 
    unsigned char buffer[POINT_BYTE_LEN];
    fin.read(reinterpret_cast<char *>(buffer), BN_BYTE_LEN+1); 
    EC_POINT_oct2point(group, A.point_ptr, buffer, POINT_BYTE_LEN, bn_ctx);
    return fin;            
}



ECPoint ECPointVector_Mul(std::vector<ECPoint> &A, std::vector<BigInt> &scalar){
    if (A.size()!=scalar.size()){
        std::cerr << "vector size does not match" << std::endl; 
    }
    size_t LEN = A.size(); 

    ECPoint result; 
    EC_POINTs_mul(group, result.point_ptr, nullptr, LEN, (const EC_POINT**)A.data(), 
        (const BIGNUM**)scalar.data(), bn_ctx);
    return std::move(result); 
}


/* Thread safe implementation for some functions */

std::string ThreadSafe_ECPointToByteString(const ECPoint& A)
{
    unsigned char buffer[POINT_BYTE_LEN]; 
    memset(buffer, 0, POINT_BYTE_LEN); 

    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
    std::string ecp_str(reinterpret_cast<char *>(buffer), POINT_BYTE_LEN);
    return std::move(ecp_str); 
}

inline void ThreadSafe_ECPoint_Mul(ECPoint &result, ECPoint &A, BigInt &scalar){
    EC_POINT_mul(group, result.point_ptr, nullptr, A.point_ptr, scalar.bn_ptr, nullptr); 
}

inline void ThreadSafe_ECPoint_Add(ECPoint &result, ECPoint &X, ECPoint &Y) 
{
    EC_POINT_add(group, result.point_ptr, X.point_ptr, Y.point_ptr, nullptr);  
}

inline void ThreadSafe_ECPoint_Sub(ECPoint &result, ECPoint &X, ECPoint &Y) 
{
    ECPoint Y_inverse = Y; 
    EC_POINT_invert(group, Y_inverse.point_ptr, nullptr); 
    EC_POINT_add(group, result.point_ptr, X.point_ptr, Y_inverse.point_ptr, nullptr);  
}


inline void ThreadSafe_ECPointVector_Mul(ECPoint &result, std::vector<ECPoint> &A, std::vector<BigInt> &scalar){
    if (A.size()!=scalar.size()){
        std::cerr << "vector size does not match" << std::endl; 
        return; 
    }
    size_t LEN = A.size(); 
    EC_POINTs_mul(group, result.point_ptr, nullptr, LEN, (const EC_POINT**)A.data(), (const BIGNUM**)scalar.data(), nullptr); 
}


/* g[i] = g[i]+h[i] */ 
void ECPointVector_Add(std::vector<ECPoint> &result, std::vector<ECPoint> &vec_A, std::vector<ECPoint> &vec_B)
{
    if (vec_A.size()!= vec_B.size()) {
        std::cerr << "vector size does not match!" << std::endl;
        exit(EXIT_FAILURE); 
    }
    #pragma omp parallel for
    for (auto i = 0; i < vec_A.size(); i++) {
        ThreadSafe_ECPoint_Add(result[i], vec_A[i], vec_B[i]); 
    }
}


void Serialize_ECPointVector(std::vector<ECPoint> &vec_A, std::ofstream &fout)
{
    for(auto i = 0; i < vec_A.size(); i++) fout << vec_A[i];  
}

void Deserialize_ECPointVector(std::vector<ECPoint> &vec_A, std::ifstream &fin)
{
    for(auto i = 0; i < vec_A.size(); i++) fin >> vec_A[i];  
}


// print an EC Point vector
void Print_ECPointVector(std::vector<ECPoint> &vec_A, std::string note)
{ 
    for (auto i = 0; i < vec_A.size(); i++)
    {
        std::cout << note << "[" << i << "]="; 
        vec_A[i].Print(); 
    }
}



/* vec_g = c * vec_g */ 
inline void ECPointVector_Scalar(std::vector<ECPoint> &result, std::vector<ECPoint> &vec_A, BigInt &c)
{
    #pragma omp parallel for
    for (auto i = 0; i < vec_A.size(); i++) {
        //result[i] = vec_A[i] * c; 
        ThreadSafe_ECPoint_Mul(result[i], vec_A[i], c);  
    } 
}


/* result[i] = A[i]*a[i] */ 
inline void ECPointVector_Product(std::vector<ECPoint> &result, std::vector<ECPoint> &vec_A, std::vector<BigInt> &vec_a)
{
    if (vec_A.size() != vec_a.size()) {
        std::cerr << "vector size does not match!" << std::endl;
        exit(EXIT_FAILURE); 
    } 
    #pragma omp parallel for
    for (auto i = 0; i < vec_A.size(); i++) {
        ThreadSafe_ECPoint_Mul(result[i], vec_A[i], vec_a[i]);  
    } 
}


/* generate a vector of random EC points */  
void GenRandomECPointVector(std::vector<ECPoint> &vec_A)
{
    for(auto i = 0; i < vec_A.size(); i++){ 
        vec_A[i] = GenRandomGenerator(); 
    }
}


/* customized hash for ECPoint class */

namespace std
{
    template <> struct hash<ECPoint>
    {
        std::size_t operator()(const ECPoint& A) const
        { 
            return std::hash<std::string>{}(ThreadSafe_ECPointToByteString(A));
        }
    };
}


#endif  // KUNLUN_EC_POINT_HPP_





