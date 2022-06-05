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


std::string ToHexString(std::string byte_str)
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
 
#endif

