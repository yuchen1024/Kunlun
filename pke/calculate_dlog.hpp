/****************************************************************************
this hpp implements DLOG algorithm 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_PARALLEL_CALCULATE_DLOG_HPP_
#define KUNLUN_PARALLEL_CALCULATE_DLOG_HPP_

/* 
** Shanks algorithm for DLOG problem: given (g, h) find x \in [0, n = 2^RANGE_LEN) s.t. g^x = h 
** g^{j*giantstep_size + i} = g^x; giantstep_num = n/giantstep_size
** babystep keytable size = 2^(RANGE_LEN/2+TRADEOFF_NUM)
** giantstep num/loop num     = 2^(RANGE_LEN/2-TRADEOFF_NUM)
*/

#include <iostream>
#include "../crypto/ec_point.hpp"
#include "../crypto/hash.hpp"
#include "../utility/murmurhash3.hpp"
#include "../utility/print.hpp"



class naivehash{
public:
    size_t operator()(const size_t& a) const
    {
        return a;
    }
};

const static size_t BUILD_TASK_NUM = pow(2, 6); 
const static size_t SEARCH_TASK_NUM = pow(2, 6);  

ECPoint ecp_giantstep; 
std::vector<ECPoint> ecp_vec_searchanchor;

/*
** key-value hash table: key is uint64_t encoding, value is its corresponding DLOG w.r.t. g
** more intuitive solution is using <ECPoint, size_t> hashmap, but its storage cost is high 
*/
std::unordered_map<size_t, size_t, naivehash> encoding2index_map; 


/*
* the default TRADEOFF_NUM=0
*/
void CheckDlogParameters(size_t RANGE_LEN, size_t TRADEOFF_NUM)
{
    if (RANGE_LEN/2 < TRADEOFF_NUM){
        std::cerr << "TRADEOFF_NUM is too aggressive" << std::endl;
        exit(EXIT_FAILURE);   
    }
}

std::string GetKeyTableFileName(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{
    std::string str_base = std::to_string(2);
    std::string str_exp  = std::to_string(RANGE_LEN/2+TRADEOFF_NUM);
    // use 8-byte uint64_t hash value as encoding of EC Point 
    std::string str_suffix = FormatToHexString(Hash::ECPointToString(g));
    str_suffix = str_suffix.substr(0,16);

    std::string keytable_filename  = str_suffix + "-babystephashkey(" + str_base + "^" + str_exp + ").table"; 
    return keytable_filename; 
}


std::string GetAuxTableFileName()
{
    std::string auxtable_filename  = "aux.table"; 
    return auxtable_filename; 
}
/* 
* parallel implementation
* include parallel keytable building 
* and parallel search
*/


/* sliced babystep build */
void BuildSlicedKeyTable(ECPoint g, ECPoint startpoint, size_t startindex, size_t SLICED_BABYSTEP_NUM, unsigned char* buffer)
{    
    size_t hashkey;
    for(auto i = 0; i < SLICED_BABYSTEP_NUM; i++)
    {
        hashkey = startpoint.ToUint64(); 
        std::memcpy(buffer+(startindex+i)*INT_BYTE_LEN, &hashkey, INT_BYTE_LEN);
        startpoint = startpoint.ThreadSafeAdd(g); 
    } 
}


/* 
* generate babystep hashkey table
* standard method is using babystep point as key for point2index hashmap: big key size
* to shorten key size, use hash to map babystep point to unique key
*/

void BuildSerializeKeyTable(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM, std::string keytable_filename)
{
    
    std::cout << keytable_filename << " does not exist, begin to build and serialize >>>" << std::endl;

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep num = giantstep size

    /*
    * to show full power of omp, this value is not real CPU core number
    * but an emprical value, should less than and dividable by BABYSTEP_NUM 
    */
    //size_t THREAD_NUM = pow(2, 6);  
    size_t SLICED_BABYSTEP_NUM = BABYSTEP_NUM/BUILD_TASK_NUM; 

    std::vector<ECPoint> startpoint(BUILD_TASK_NUM); 
    std::vector<size_t> startindex(BUILD_TASK_NUM); 

    #pragma omp parallel for
    for (auto i = 0; i < BUILD_TASK_NUM; i++){
        startindex[i] = i * SLICED_BABYSTEP_NUM; 
    }
    #pragma omp parallel for
    for (auto i = 0; i < BUILD_TASK_NUM; i++){
        startpoint[i] = g.ThreadSafeMul(startindex[i]);
    }
    

    // allocate memory
    unsigned char *buffer = new unsigned char[BABYSTEP_NUM*INT_BYTE_LEN]();
    if(buffer == nullptr)
    {
        std::cerr << "fail to create buffer for babystep table" << std::endl; 
        exit(EXIT_FAILURE); 
    } 

    #pragma omp parallel for
    for(auto i = 0; i < BUILD_TASK_NUM; i++){ 
        BuildSlicedKeyTable(g, startpoint[i], startindex[i], SLICED_BABYSTEP_NUM, buffer);
    }  

    // save buffer to babystep table
    // auto start_time = std::chrono::steady_clock::now(); // start to count the time
    std::ofstream fout; 
    fout.open(keytable_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << keytable_filename << " open error" << std::endl;
        exit(1); 
    }
    fout.write(reinterpret_cast<char *>(buffer), BABYSTEP_NUM*INT_BYTE_LEN); 

    fout.close(); 
    delete[] buffer; 
        
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "serializing babystep keytable takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

void BuildSerializeAuxTable(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM, std::string auxtable_filename)
{

    size_t BABYSTEP_NUM  = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep_num = giantstep_size
    size_t GIANTSTEP_NUM = pow(2, RANGE_LEN/2 - TRADEOFF_NUM); 
    
    size_t SLICED_GIANTSTEP_NUM = GIANTSTEP_NUM/SEARCH_TASK_NUM; 

    // compute and save ecp_giantstep and ecp_slicedrange
    ECPoint ecp_giantstep = g * BigInt(BABYSTEP_NUM); // set giantstep = g^babystep_num
    ecp_giantstep = ecp_giantstep.Invert();

    ecp_giantstep.Print("giantstep"); 
    
    ECPoint ecp_slicedrange = ecp_giantstep * BigInt(SLICED_GIANTSTEP_NUM);

    ecp_vec_searchanchor.resize(SEARCH_TASK_NUM); 

    for (auto i = 0; i < SEARCH_TASK_NUM; i++){
        ecp_vec_searchanchor[i] = ecp_slicedrange * BigInt(i);         
    }

    std::ofstream fout; 
    fout.open(auxtable_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << auxtable_filename << " open error" << std::endl;
        exit(1); 
    }
    fout << ecp_giantstep; 

    for (auto i = 0; i < SEARCH_TASK_NUM; i++){
        fout << ecp_vec_searchanchor[i];         
    }

    fout.close();

    ecp_giantstep.Print("giantstep");  
}

/* deserialize keytable and build hashmap */
void DeserializeKeyTableBuildHashMap(std::string keytable_filename, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{   
    std::cout << keytable_filename << " already exists, begin to load and build the hashmap >>>" << std::endl; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); 

    unsigned char* buffer = new unsigned char[BABYSTEP_NUM*INT_BYTE_LEN]();  
    if(buffer == nullptr)
    {
        std::cerr << "fail to create buffer for babystep table" << std::endl; 
        exit(EXIT_FAILURE); 
    }   
    // load hashmap_file to buffer
    std::ifstream fin; 
    fin.open(keytable_filename, std::ios::binary); 
    if(!fin)
    {
        std::cout << keytable_filename << " read error" << std::endl;
        exit(EXIT_FAILURE); 
    }
    fin.seekg(0, fin.end);
    size_t FILE_BYTE_LEN = fin.tellg(); // get the size of hash table file 

    if (FILE_BYTE_LEN != BABYSTEP_NUM * INT_BYTE_LEN)
    {
        std::cout << "buffer size does not match babystep table size" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    std::cout << keytable_filename << " size = " << (double)FILE_BYTE_LEN/pow(2,20) << " MB" << std::endl;

    fin.seekg(0);                  // reset the file pointer to the beginning of file
    
    fin.read(reinterpret_cast<char*>(buffer), FILE_BYTE_LEN); // read file from disk to RAM

    fin.close(); 
    // auto end_time = std::chrono::steady_clock::now(); // end to count the time
    // auto running_time = end_time - start_time;
    // std::cout << "deserializing babystep table takes time = " 
    // << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    // construct hashmap from buffer 
    start_time = std::chrono::steady_clock::now(); // start to count the time
    std::size_t hashkey; 

    /* point_to_index_map[ECn_to_String(babystep)] = i */
    for(auto i = 0; i < BABYSTEP_NUM; i++)
    {
        std::memcpy(&hashkey, buffer+i*INT_BYTE_LEN, INT_BYTE_LEN);
        encoding2index_map[hashkey] = i; 
    }

    delete[] buffer; 

    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "building hashmap takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
} 

void DeserializeAuxTable(std::string auxtable_filename, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{   
    std::cout << auxtable_filename << " already exists, begin to load and build the hashmap >>>" << std::endl; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time

    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); 
 
    // load hashmap_file to buffer
    std::ifstream fin; 
    fin.open(auxtable_filename, std::ios::binary); 
    // if(!fin)
    // {
    //     std::cout << auxtable_filename << " read error" << std::endl;
    //     exit(EXIT_FAILURE); 
    // }
    // fin.seekg(0, fin.end);
    // size_t FILE_BYTE_LEN = fin.tellg(); // get the size of hash table file 

    // if (FILE_BYTE_LEN != (SEARCH_TASK_NUM+1) * POINT_COMPRESSED_BYTE_LEN)
    // {
    //     std::cout << "aux table size does not match" << std::endl; 
    //     exit(EXIT_FAILURE); 
    // }

    // std::cout << auxtable_filename << " size = " << (double)FILE_BYTE_LEN/pow(2,20) << " MB" << std::endl;

    // fin.seekg(0);                  // reset the file pointer to the beginning of file
    
    // ECPoint temp = ECPoint(generator);
    // temp.Print();  
    // fin >> temp; 


    // std::cout << "here?" << std::endl;


    // temp.Print(); 

    ecp_giantstep = ECPoint(generator); 

    std::cout << "where?" << std::endl;

    // ecp_vec_searchanchor.resize(SEARCH_TASK_NUM); 
    
    // std::cout << "why" << std::endl;
    // for(auto i = 0; i < SEARCH_TASK_NUM; i++){
    //     fin >> ecp_vec_searchanchor[i]; 
    // }

    // std::cout << "oh no" << std::endl;

    fin.close(); 


    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "load aux table takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
} 



/* parallelizable search task */
bool SearchSlicedRange(size_t SEARCH_TASK_INDEX, ECPoint target, size_t SLICED_GIANTSTEP_NUM, size_t &i, size_t &j)
{    
    target = target.ThreadSafeAdd(ecp_vec_searchanchor[SEARCH_TASK_INDEX]); 
    std::size_t hashkey; 
    // giant-step and baby-step search
    for(j = 0; j < SLICED_GIANTSTEP_NUM; j++)
    {
        // map the point to keyvalue
        hashkey = target.ToUint64(); 
        // baby-step search in the hash map
        if (encoding2index_map.find(hashkey) == encoding2index_map.end())
        { 
            target = target.ThreadSafeAdd(ecp_giantstep); 
        }
        else{
            i = encoding2index_map[hashkey]; 
            return true;
        }
    }
    return false; 
}


// compute x = log_g h
bool ShanksDLOG(const ECPoint &g, const ECPoint &h, size_t RANGE_LEN, size_t TRADEOFF_NUM, BigInt &x)
{
    size_t BABYSTEP_NUM  = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep_num = giantstep_size
    size_t GIANTSTEP_NUM = pow(2, RANGE_LEN/2 - TRADEOFF_NUM); 

    size_t SLICED_GIANTSTEP_NUM = GIANTSTEP_NUM/SEARCH_TASK_NUM; 


    ecp_giantstep.Print("giantstep"); 

    PrintECPointVector(ecp_vec_searchanchor, "anchor");

 
    
    /* begin to search */
    std::vector<size_t> i_index(SEARCH_TASK_NUM); 
    std::vector<size_t> j_index(SEARCH_TASK_NUM);

    // check if the hash map is empty
    if(encoding2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        exit (EXIT_FAILURE);
    }

    volatile bool FIND = false;

    //#pragma omp parallel for shared(FIND)
    for(auto i = 0; i < SEARCH_TASK_NUM; i++){
        if(FIND==false)
        {
            if(SearchSlicedRange(i, h, SLICED_GIANTSTEP_NUM, i_index[i], j_index[i]))
            {
                x = BigInt(i_index[i]) + BigInt(j_index[i]+i*SLICED_GIANTSTEP_NUM) * BigInt(BABYSTEP_NUM); 
                FIND = true;
            } 
        } 
    }

    return FIND; 
}


# endif