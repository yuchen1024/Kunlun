#ifndef KUNLUN_EC25519_HPP_
#define KUNLUN_EC25519_HPP_

#include "ec_group.hpp"
#include "../utility/routines.hpp"


/* 
** x25519 in OpenSSL is not available for outside invoke 
** here we do some hacking to make it public accessable
** interface for curve 25519 multiplication
*/
extern "C"
{
void x25519_scalar_mulx(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
}

// define ECPoint on curve 25519
class EC25519Point{
public:
    uint8_t px[32];

    // constructor functions
    EC25519Point(); 
    EC25519Point(const EC25519Point& other);
    
    // Creates an ECPoint object with given x, y affine coordinates.
    EC25519Point(const uint8_t* buffer);

    // EC point group operations
    
    // Returns an ECPoint whose value is (this * scalar).
    EC25519Point Mul(const std::vector<uint8_t> scalar) const;

    // Returns an ECPoint whose value is (this + other).
    EC25519Point XOR(const EC25519Point& other) const;

    // Returns true if this equals point, false otherwise.
    bool CompareTo(const EC25519Point& point) const;

    inline EC25519Point& operator=(const EC25519Point& other) {
        memcpy(this->px, other.px, 32); 
        return *this; 
    }

    inline std::string ToByteString() const;
    
    inline bool operator==(const EC25519Point& other) const{ return this->CompareTo(other); }

    inline bool operator!=(const EC25519Point& other) const{ return !this->CompareTo(other);}

    inline EC25519Point operator*(const std::vector<uint8_t> scalar) const { return this->Mul(scalar); }

    inline EC25519Point operator^(const EC25519Point& other) const { return this->XOR(other); }

    inline EC25519Point& operator*=(const std::vector<uint8_t> scalar) { return *this = *this * scalar; }

    inline EC25519Point& operator^=(const EC25519Point& other) { return *this = *this ^ other; }

    void Print() const;

    void Print(std::string note) const;  


    friend std::ofstream &operator<<(std::ofstream &fout, EC25519Point &A); 
 
    friend std::ifstream &operator>>(std::ifstream &fin, EC25519Point &A);
};


// initialize as a all zero byte array
EC25519Point::EC25519Point(){
    memset(this->px, '0', 32); 
}

EC25519Point::EC25519Point(const EC25519Point& other){
    memcpy(this->px, other.px, 32);
}

EC25519Point::EC25519Point(const uint8_t* buffer){
    memcpy(this->px, buffer, 32);
}

EC25519Point EC25519Point::Mul(const std::vector<uint8_t> scalar) const {
    EC25519Point result; 
    x25519_scalar_mulx(result.px, scalar.data(), this->px); 
    return result;
}

EC25519Point EC25519Point::XOR(const EC25519Point& other) const {  
    EC25519Point result;
    int thread_num = omp_get_thread_num();
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for(auto i = 0; i < 32; i++){
        result.px[i] = this->px[i]^other.px[i];
    }
    return result; 
}

bool EC25519Point::CompareTo(const EC25519Point& other) const{
    return std::equal(this->px, this->px+32, other.px, other.px+32);
}


// convert an EC25519 Point to byte string
std::string EC25519Point::ToByteString() const
{
    std::string ecp_str(32, '0'); 
    memcpy(&ecp_str[0], this->px, 32); 
    return ecp_str; 
}

void EC25519Point::Print() const
{ 
    for(auto i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(this->px[i]);
    } // print in hex string
    std::cout << std::dec << std::endl; 
}

// print an EC point with note
void EC25519Point::Print(std::string note) const
{ 
    std::cout << note << " = "; 
    this->Print(); 
}

std::ofstream &operator<<(std::ofstream &fout, EC25519Point &A)
{ 
    fout.write(reinterpret_cast<char *>(A.px), 32); 
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, EC25519Point &A)
{ 
    fin.read(reinterpret_cast<char *>(A.px), 32); 
    return fin;            
}

class EC25519PointHash{
public:
    size_t operator()(const EC25519Point& A) const
    {
        return std::hash<std::string>{}(A.ToByteString());
    }
};

auto EC25519Point_Lexical_Compare = [](EC25519Point A, EC25519Point B){ 
    return A.ToByteString() < B.ToByteString(); 
};


#endif