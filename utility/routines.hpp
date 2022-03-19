/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_UTILITY_ROUTINES_HPP_
#define KUNLUN_UTILITY_ROUTINES_HPP_

#include "../include/std.inc"

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

std::ofstream &operator<<(std::ofstream &fout, const size_t &a)
{ 
    fout.write(reinterpret_cast<const char *>(&a), 8);  
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, size_t &a)
{ 
    fin.read(reinterpret_cast<char *>(&a), 8); 
    return fin;            
}

std::ofstream &operator<<(std::ofstream &fout, const int64_t &a)
{ 
    fout.write(reinterpret_cast<const char *>(&a), 8);  
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, int64_t &a)
{ 
    fin.read(reinterpret_cast<char *>(&a), 8); 
    return fin;            
}

std::ofstream &operator<<(std::ofstream &fout, const uint64_t &a)
{ 
    fout.write(reinterpret_cast<const char *>(&a), 8);  
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, uint64_t &a)
{ 
    fin.read(reinterpret_cast<char *>(&a), 8); 
    return fin;            
}

std::ofstream &operator<<(std::ofstream &fout, const uint8_t &a)
{ 
    fout.write(reinterpret_cast<const char *>(&a), 1);  
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, uint8_t &a)
{ 
    fin.read(reinterpret_cast<char *>(&a), 1); 
    return fin;            
}

void SerializeUintVector(const std::vector<uint8_t> &vec_a, std::ofstream &fout)
{
    for(auto i = 0; i < vec_a.size(); i++) fout << vec_a[i];  
}

void DeserializeUintVector(std::vector<uint8_t> &vec_a, std::ifstream &fin)
{
    for(auto i = 0; i < vec_a.size(); i++) fin >> vec_a[i];  
}

  
#endif

