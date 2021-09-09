/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef COMMON_ROUTINES_HPP_
#define COMMON_ROUTINES_HPP_

#include <iostream>
#include <fstream>
#include <string>

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


// strings converted from unsigned char[] may not printable, convert them to hex form to easy debug
std::string StringToHex(std::string input)
{
    std::string result; 
    boost::algorithm::hex(input.begin(), input.end(), std::back_inserter(result));
    return std::move(result); 
}
  
#endif

