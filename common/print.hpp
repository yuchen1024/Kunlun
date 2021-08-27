/****************************************************************************
this hpp implements print functionality
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef COMMOM_PRINT_HPP_
#define COMMOM_PRINT_HPP_

#include <iostream>

const static size_t LINE_LEN = 120;     // the length of split line

/* print split line */
void Print_SplitLine(char ch)
{
    for (auto i = 0; i < LINE_LEN; i++) std::cout << ch;  
    std::cout << std::endl;
}

#endif // COMMON_PRINT_HPP_