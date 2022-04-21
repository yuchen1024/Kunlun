/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_SERIALIZATION_HPP_
#define KUNLUN_SERIALIZATION_HPP_

#include "../include/std.inc"
#include "../config/config.h"

namespace Serialization{

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

template <> // specialize for string
std::ofstream &operator<<<std::string>(std::ofstream &fout, const std::string& str)
{
    size_t LEN = str.size();
    fout << LEN; 
    fout.write(reinterpret_cast<const char *>(&str[0]), str.size()); 
    return fout; 
}

template <> // specialize for string
std::ifstream &operator>><std::string>(std::ifstream &fin, std::string& str)
{
    size_t LEN; 
    fin >> LEN;
    str.resize(LEN); 
    fin.read(reinterpret_cast<char *>(&str[0]), str.size()); 
    return fin; 
}
}
  
#endif
