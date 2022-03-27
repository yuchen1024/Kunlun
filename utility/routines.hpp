/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_UTILITY_ROUTINES_HPP_
#define KUNLUN_UTILITY_ROUTINES_HPP_

#include "../include/std.inc"
#include "../config/config.h"


// check the existence of a given file
inline bool FileExist(const std::string& filename)
{
    bool existing_flag; 
    std::ifstream fin; 
    fin.open(filename);
    if(!fin)  existing_flag = false;    
    else existing_flag = true;
    return existing_flag; 
}


std::string FormatToHexString(std::string byte_str)
{
    std::string hex_str;
    std::stringstream ss;

    for (const auto &item : byte_str) {
        ss << std::hex << int(item);
    }
    hex_str = ss.str();

    // format to uppercase
    for (auto & c: hex_str) c = toupper(c);
    return hex_str;
}

// A simple trick to decide if x = 2^n for n > 0 and x > 0
bool IsPowerOfTwo(size_t x)
{
    return (x != 0) && ((x & (x - 1)) == 0);
}

std::vector<int64_t> GenRandomIntegerVectorLessThan(size_t LEN, int64_t MAX)
{
    std::vector<int64_t> vec_result(LEN); 
    srand(time(0));
    for(auto i = 0; i < LEN; i++)
    {
        vec_result[i] = rand() % MAX;
    }
    return vec_result; 
}

// #ifdef IS_MACOS
// std::ofstream &operator<<(std::ofstream &fout, const size_t &a)
// { 
//     //std::cout << "OS name: " << OS_NAME << std::endl;
//     fout.write(reinterpret_cast<const char *>(&a), 8);  
//     return fout;            
// }
 
// std::ifstream &operator>>(std::ifstream &fin, size_t &a)
// { 
//     fin.read(reinterpret_cast<char *>(&a), 8); 
//     return fin;            
// }
// #endif


template <typename ElementType> // Note: T must be a C++ POD type.
std::ofstream &operator<<(std::ofstream &fout, const ElementType& element)
{
    fout.write(reinterpret_cast<const char *>(&element), sizeof(ElementType)); 
    return fout; 
}


template <typename ElementType> // Note: T must be a C++ POD type.
std::ifstream &operator>>(std::ifstream &fin, ElementType& element)
{
    fin.read(reinterpret_cast<char *>(&element), sizeof(ElementType)); 
    return fin; 
}


template <typename ElementType> // Note: T must be a C++ POD type.
std::ofstream &operator<<(std::ofstream &fout, const std::vector<ElementType>& vec_element)
{
    fout.write(reinterpret_cast<const char *>(vec_element.data()), vec_element.size() * sizeof(ElementType)); 
    return fout; 
}

template <typename ElementType> // Note: T must be a C++ POD type.
std::ifstream &operator>>(std::ifstream &fin, std::vector<ElementType>& vec_element)
{ 
    fin.read(reinterpret_cast<char *>(vec_element.data()), vec_element.size() * sizeof(ElementType)); 
    return fin; 
}


template < > // specialize for string
std::ofstream &operator<<<std::string>(std::ofstream &fout, const std::string& str)
{
    fout.write(reinterpret_cast<const char *>(str.data()), str.size()); 
    return fout; 
}

template < > // specialize for string
std::ifstream &operator>><std::string>(std::ifstream &fin, std::string& str)
{
    std::ostringstream ss; 
    ss << fin.rdbuf();
    str = std::string(ss.str()); 
    return fin; 
}


  
#endif

