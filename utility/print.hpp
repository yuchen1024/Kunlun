/****************************************************************************
this hpp implements print functionality
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_UTILITY_PRINT_HPP_
#define KUNLUN_UTILITY_PRINT_HPP_

#include <iostream>

const static size_t LINE_LEN = 120;     // the length of split line


/* print split line */
void PrintSplitLine(char ch)
{
    for (auto i = 0; i < LINE_LEN; i++) std::cout << ch;  
    std::cout << std::endl;
}

// print uint_8 in hex
void PrintBytes(uint8_t* A, size_t LEN)
{
    for(auto i = 0; i < LEN; i++)
        std::cout << std::hex << +A[i] << " ";
    std::cout << std::endl;
}


void PrintBitMatrix(uint8_t *M, size_t ROW_NUM, size_t COLUMN_NUM)
{
    uint8_t mask = 0X80;
    //std::cout << int(mask) << std::endl;
    uint8_t *temp = new uint8_t [ROW_NUM/8 * COLUMN_NUM];
    memcpy(temp, M, ROW_NUM/8 * COLUMN_NUM);  
    uint8_t T[ROW_NUM*COLUMN_NUM]; 
    for(auto i = 0; i < ROW_NUM*COLUMN_NUM; i++){
        if((temp[i/8]&mask) == 0X80) T[i] = 1;
        else T[i] = 0; 
        temp[i/8] = temp[i/8] << 1;  
    }

    for(auto i = 0; i < ROW_NUM; i++){
        for(auto j = 0; j < COLUMN_NUM; j++){
            if(T[j*ROW_NUM+i] == 0) std::cout << 0 << " ";
            else std::cout << 1 << " "; 
        }
        std::cout << std::endl; 
    }
    std::cout << std::endl; 
    delete[] temp;
}


#endif // COMMON_PRINT_HPP_