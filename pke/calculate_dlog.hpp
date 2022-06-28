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
** giantstep num/loop num = 2^(RANGE_LEN/2-TRADEOFF_NUM)
*/

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


const static size_t BUILD_TASK_NUM  = pow(2, 6);  // number of parallel task for building pre-computable table 
const static size_t SEARCH_TASK_NUM = pow(2, 6);  // number of parallel task for search  

const static size_t KEY_LEN = 8; // the key length for hashtable


ECPoint giantstep; 
std::vector<ECPoint> vec_searchanchor;

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

std::string GetTableFileName(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{
    std::string str_base = std::to_string(2);
    std::string str_exp0 = std::to_string(RANGE_LEN);    // range size
    std::string str_exp1 = std::to_string(RANGE_LEN/2+TRADEOFF_NUM);  // babystep key table size
    std::string str_exp2 = std::to_string(RANGE_LEN/2-TRADEOFF_NUM-(size_t)log2(SEARCH_TASK_NUM));  // (log) giant step amplification factor: default value=0 
    // use 8-byte uint64_t hash value as an identifier of EC Point 
    std::string str_suffix = ToHexString(Hash::ECPointToString(g));
    str_suffix = str_suffix.substr(0,16);

    std::string table_filename  = str_suffix +"[" + 
                                  str_base+"^"+str_exp0 + "," + 
                                  str_base+"^"+str_exp1 + "," + 
                                  str_base+"^"+str_exp2 + "].table"; 
    return table_filename; 
}

/* 
* parallel implementation: parallel table building and parallel search
*/


/* sliced babystep build */
void BuildSlicedKeyTable(ECPoint g, ECPoint startpoint, size_t startindex, size_t SLICED_BABYSTEP_NUM, unsigned char* buffer)
{    
    size_t hashkey;
    for(auto i = 0; i < SLICED_BABYSTEP_NUM; i++)
    {
        hashkey = startpoint.ToUint64(); 
        std::memcpy(buffer+(startindex+i)*KEY_LEN, &hashkey, KEY_LEN);
        startpoint = startpoint + g; 
    } 
}

/* 
** generate precompute table, it consists of two parts

** part 1 - babystep hashkey: encoding values of [g^0, g^1, ..., g^{BABYSTEP_NUM}]
** standard method is using babystep point as key for point2index hashmap, result in big key size
** to shorten key size, use hash to map babystep point to unique key

** part 2 - giantstep aux info: (1) giantstep = - g^{BABYSTEP_NUM}; (2) [giantstep^{i*factor}]: i=[SEARCH_TASK_NUM]

*/

void BuildSaveTable(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM, std::string table_filename)
{
    
    std::cout << "begin to build and save " << table_filename << " >>> " << std::endl;

    auto start_time = std::chrono::steady_clock::now(); // start to count the time

    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep num = single giantstep size

    /*
    * to show full power of omp, this value is not real CPU core number
    * but an emprical value, should less than and dividable by BABYSTEP_NUM 
    */

    size_t SLICED_BABYSTEP_NUM = BABYSTEP_NUM/BUILD_TASK_NUM; 

    std::vector<ECPoint> startpoint(BUILD_TASK_NUM); 
    std::vector<size_t> startindex(BUILD_TASK_NUM); 

    #pragma omp parallel for num_threads(thread_count)
    for (auto i = 0; i < BUILD_TASK_NUM; i++){
        startindex[i] = i * SLICED_BABYSTEP_NUM;  // generate start index
        startpoint[i] = g * startindex[i];     // compute start point
    }
    
    // allocate memory
    unsigned char *buffer = new unsigned char[BABYSTEP_NUM*KEY_LEN]();
    if(buffer == nullptr)
    {
        std::cerr << "fail to create buffer for babystep key table" << std::endl; 
        exit(EXIT_FAILURE); 
    } 

    // part 1: parallel build babystep key 
    #pragma omp parallel for num_threads(thread_count)
    for(auto i = 0; i < BUILD_TASK_NUM; i++){ 
        BuildSlicedKeyTable(g, startpoint[i], startindex[i], SLICED_BABYSTEP_NUM, buffer);
    }  

    // part 2: build giantstep aux info 
    size_t GIANTSTEP_NUM = pow(2, RANGE_LEN/2 - TRADEOFF_NUM); 
    
    /*
    ** each search task will search in #SLICED_GIANTSTEP_NUM GIANTSTEP
    ** the maximum SEACRH_TASK_NUM = GIANTSTEP_NUM
    */
    size_t SLICED_GIANTSTEP_NUM = GIANTSTEP_NUM/SEARCH_TASK_NUM; 

    // compute and save giantstep and anchor points for slicedrange
    giantstep.ReInitialize(); 
    giantstep = g * BigInt(BABYSTEP_NUM); 
    giantstep = giantstep.Invert();   // set giantstep = -g^BABYSTEP_NUM
    
    ECPoint giantgiantstep = giantstep * BigInt(SLICED_GIANTSTEP_NUM);

    vec_searchanchor.resize(SEARCH_TASK_NUM); 
    #pragma omp parallel for num_threads(thread_count)
    for (auto i = 0; i < SEARCH_TASK_NUM; i++){
        vec_searchanchor[i] = giantgiantstep * (BigInt(i));         
    }

    std::ofstream fout; 
    fout.open(table_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << table_filename << " open error" << std::endl;
        exit(1); 
    }

    // save babystep key to table
    fout.write(reinterpret_cast<char *>(buffer), BABYSTEP_NUM*KEY_LEN); 
    delete[] buffer;

    // save giantstep aux info to table
    fout << giantstep; 
    for (auto i = 0; i < SEARCH_TASK_NUM; i++){
        fout << vec_searchanchor[i];         
    }

    fout.close(); 
        
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "build and save precompute table takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

/* 
** load table 
** 1. build hashmap in RAM
** 2. load aux info to global objects
*/ 
void LoadTable(std::string table_filename, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{   
    std::cout << "begin to load " << table_filename << " >>>" << std::endl; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    
    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); 

    // read and check table file
    std::ifstream fin; 
    fin.open(table_filename, std::ios::binary); 
    if(!fin)
    {
        std::cout << table_filename << " read error" << std::endl;
        exit(EXIT_FAILURE); 
    }
    fin.seekg(0, fin.end);

    size_t FILE_BYTE_LEN = fin.tellg(); // get the size of hash table file 
    size_t BABYSTEP_KEY_SIZE = BABYSTEP_NUM * KEY_LEN; 

    #ifdef ECPOINT_COMPRESSED
        size_t GIANTSTEP_AUX_SIZE = (SEARCH_TASK_NUM+1) * POINT_COMPRESSED_BYTE_LEN; 
    #else
        size_t GIANTSTEP_AUX_SIZE = (SEARCH_TASK_NUM+1) * POINT_BYTE_LEN;
    #endif

    if (FILE_BYTE_LEN != (BABYSTEP_KEY_SIZE+GIANTSTEP_AUX_SIZE))
    {
        std::cout << "table size does not match" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    std::cout << table_filename << " size = " << (double)FILE_BYTE_LEN/pow(2,20) << " MB" << std::endl;

    fin.seekg(0);                  // reset the file pointer to the beginning of file

    // construct hashmap from babystep key 
    unsigned char* buffer = new unsigned char[BABYSTEP_NUM*KEY_LEN]();  
    if(buffer == nullptr)
    {
        std::cerr << "fail to create buffer for babystep table" << std::endl; 
        exit(EXIT_FAILURE); 
    }
    fin.read(reinterpret_cast<char*>(buffer), BABYSTEP_KEY_SIZE); // read file from disk to RAM

    #pragma omp parallel
    #pragma omp sections
    {
        #pragma omp section
        {
            size_t hashkey; 
            encoding2index_map.reserve(BABYSTEP_NUM); 
            /* point_to_index_map[ECn_to_String(babystep)] = i */
            for(auto i = 0; i < BABYSTEP_NUM; i++)
            {
                std::memcpy(&hashkey, buffer+i*KEY_LEN, KEY_LEN);
                encoding2index_map[hashkey] = i; 
            }
            delete[] buffer; 
        }

        #pragma omp section
        {
            giantstep.ReInitialize();
            fin >> giantstep; 
            vec_searchanchor.resize(SEARCH_TASK_NUM); 
            for(auto i = 0; i < SEARCH_TASK_NUM; i++){
                fin >> vec_searchanchor[i]; 
            }
            fin.close(); 
        }
    }
    
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "load table (build hashmap + aux info) takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
} 


/* parallelizable search task */
bool SearchSlicedRange(size_t SEARCH_TASK_INDEX, ECPoint target, size_t &SLICED_GIANTSTEP_NUM, 
                       size_t &babystep_index, size_t &giantstep_index, bool &FIND)
{    
    // obtain relative target in sliced range
    target = target + vec_searchanchor[SEARCH_TASK_INDEX]; 
    size_t hashkey; 
    // giantgiant-step 
    for(giantstep_index = 0; giantstep_index < SLICED_GIANTSTEP_NUM; giantstep_index++)
    {
        // giantstep search in each loop
        if(FIND == true) break; 
        // map the point to keyvalue
        hashkey = target.ToUint64(); 

        // baby-step search in the hash map
        if (encoding2index_map.find(hashkey) == encoding2index_map.end())
        { 
            target = target + giantstep; 
        }
        else{
            babystep_index = encoding2index_map[hashkey]; 
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
    
    /* begin to search */
    std::vector<size_t> babystep_index(SEARCH_TASK_NUM); 
    std::vector<size_t> giantstep_index(SEARCH_TASK_NUM); // relative giantstep index in sub-search task

    // check if the hash map is empty
    if(encoding2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        exit (EXIT_FAILURE);
    }

    // a beacon value: used to notify other tasks break if one task has already succeed
    bool FIND = false;

    #pragma omp parallel for shared(FIND) num_threads(thread_count)
    for(auto i = 0; i < SEARCH_TASK_NUM; i++){
        if(FIND == false)
        {
            if(SearchSlicedRange(i, h, SLICED_GIANTSTEP_NUM, babystep_index[i], giantstep_index[i], FIND) == true)
            {
                x = BigInt(babystep_index[i]) + BigInt(giantstep_index[i]+i*SLICED_GIANTSTEP_NUM) * BigInt(BABYSTEP_NUM); 
                FIND = true;
            } 
        } 
    }

    return FIND; 
}


# endif