/****************************************************************************
this hpp implements DLOG algorithm 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef PKE_CALCULATE_DLOG_HPP_
#define PKE_CALCULATE_DLOG_HPP_

/* 
    Shanks algorithm for DLOG problem: given (g, h) find x \in [0, n = 2^RANGE_LEN) s.t. g^x = h 
    g^{j*giantstep_size + i} = g^x; giantstep_num = n/giantstep_size
*/

#include "../crypto/ec_point.hpp"

#include <thread>
#include <vector>

class naivehash{
public:
    size_t operator()(const size_t& a) const
    {
        return a;
    }
};


// key-value hash table: key is integer, value is its corresponding DLOG w.r.t. g
std::unordered_map<size_t, size_t, naivehash> int2index_map; 


/* 
* parallel implementation
* include parallel keytable building 
* and parallel search
*/


/* sliced babystep build */
void Build_Sliced_KeyTable(ECPoint &g, ECPoint &startpoint, size_t startindex, size_t sliced_babystep_num, unsigned char* buffer)
{    
    size_t hashkey; 
    for(auto i = 0; i < sliced_babystep_num; i++)
    {
        hashkey = std::hash<std::string>{}(ThreadSafe_ECPointToByteString(startpoint)); 
        std::memcpy(buffer+(startindex+i)*INT_LEN, &hashkey, INT_LEN);
        ThreadSafe_ECPoint_Add(startpoint, g, startpoint); 
    } 
}


/* 
* generate babystep hashkey table
* standard method is using babystep point as key for point2index hashmap: big key size
* to shorten key size, use hash to map babystep point to unique key
*/

void Parallel_Build_Serialize_KeyTable(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM, 
                                       size_t THREAD_NUM, std::string keytable_filename)
{
    std::cout << "babystep hashkey table does not exist, begin to build and serialize >>>" << std::endl;

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    size_t babystep_num = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep num = giantstep size

    if(babystep_num%THREAD_NUM != 0)
    {
        std::cout << "thread assignment fails" << std::endl; 
        exit(EXIT_FAILURE); 
    }
    size_t sliced_babystep_num = babystep_num/THREAD_NUM; 

    std::vector<ECPoint> startpoint(THREAD_NUM); 
    std::vector<size_t> startindex(THREAD_NUM); 

    //#pragma omp parallel// NEW ADD
    for (auto i = 0; i < THREAD_NUM; i++){
        startindex[i] = i * sliced_babystep_num; 
        startpoint[i] = g * BigInt(startindex[i]);
    } 

    // allocate memory
    unsigned char *buffer = new unsigned char[babystep_num*INT_LEN]();
    if(buffer == nullptr)
    {
        std::cout << "fail to create buffer for babystep table" << std::endl; 
        exit(EXIT_FAILURE); 
    } 

    std::vector<std::thread> initialize_task;
    for(auto i = 0; i < THREAD_NUM; i++){ 
        initialize_task.push_back(std::thread(Build_Sliced_KeyTable, std::ref(g), std::ref(startpoint[i]), 
                                  std::ref(startindex[i]), std::ref(sliced_babystep_num), std::ref(buffer)));
    }

    for(auto i = 0; i < THREAD_NUM; i++){ 
        initialize_task[i].join(); 
    }  

    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "building babystep hashkey table takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;  


    // save buffer to babystep table
    start_time = std::chrono::steady_clock::now(); // start to count the time
    std::ofstream fout; 
    fout.open(keytable_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << keytable_filename << " open error" << std::endl;
        exit(1); 
    }
    fout.write(reinterpret_cast<char *>(buffer), babystep_num*INT_LEN); 
    fout.close(); 
    delete[] buffer; 
        
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "serializing babystep table takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

/* deserialize keytable and build hashmap */
void Deserialize_KeyTable_Build_HashMap(std::string keytable_filename, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{   
    std::cout << "babystep table already exists, begin to load and build the hashmap >>>" << std::endl; 

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    size_t babystep_num = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); 

    unsigned char* buffer = new unsigned char[babystep_num*INT_LEN]();  
    if(buffer == nullptr)
    {
        std::cout << "fail to create buffer for babystep table" << std::endl; 
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
    size_t FILE_LEN = fin.tellg(); // get the size of hash table file 

    if (FILE_LEN != babystep_num*INT_LEN)
    {
        std::cout << "buffer size does not match babystep table size" << std::endl; 
        exit(EXIT_FAILURE); 
    }

    std::cout << keytable_filename << " size = " << FILE_LEN/pow(2,20) << " MB" << std::endl;

    fin.seekg(0);                  // reset the file pointer to the beginning of file
    fin.read(reinterpret_cast<char*>(buffer), FILE_LEN); // read file from disk to RAM
    fin.close(); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "deserializing babystep table takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    // construct hashmap from buffer 
    start_time = std::chrono::steady_clock::now(); // start to count the time
    std::size_t hashkey; 


    /* point_to_index_map[ECn_to_String(babystep)] = i */
    for(auto i = 0; i < babystep_num; i++)
    {
        std::memcpy(&hashkey, buffer+i*INT_LEN, INT_LEN);
        int2index_map[hashkey] = i; 
    }

    delete[] buffer; 
    
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "building hashmap takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
} 


/* parallelizable search task */
void Search_Sliced_Range(ECPoint &ecp_searchanchor, ECPoint &ecp_giantstep, 
                         size_t sliced_giantstep_num, size_t &i, size_t &j, 
                         int &finding, int &parallel_finding)
{    
    std::size_t hashkey; 
    // giant-step and baby-step search
    for(j = 0; j < sliced_giantstep_num; j++)
    {
        /* If key not found in map iterator to end is returned */ 
        if (parallel_finding == 1) break; 
        // map the point to keyvalue
        hashkey = std::hash<std::string>{}(ThreadSafe_ECPointToByteString(ecp_searchanchor)); 
        
        // baby-step search in the hash map
        if (int2index_map.find(hashkey) == int2index_map.end())
        {
            //ecp_searchanchor = ecp_searchanchor + ecp_giantstep; // not found, take a giant-step forward   
            ThreadSafe_ECPoint_Add(ecp_searchanchor, ecp_giantstep, ecp_searchanchor); 
        }
        else{
            i = int2index_map[hashkey]; 
            finding = 1; 
            parallel_finding = 1; 
            break;
        }
    }
}


// compute x = log_g h
bool Parallel_Shanks_DLOG(const ECPoint &g, const ECPoint &h, size_t RANGE_LEN, size_t TRADEOFF_NUM, size_t THREAD_NUM, BigInt &x)
{
    size_t babystep_num  = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); 
    size_t giantstep_num = pow(2, RANGE_LEN/2 - TRADEOFF_NUM); 

    /* compute the giantstep */
    ECPoint ecp_giantstep = g * BigInt(babystep_num); // set giantstep = g^babystep_num
    ecp_giantstep = ecp_giantstep.Invert();
 
    if(giantstep_num%THREAD_NUM != 0)
    {
        std::cerr << "thread assignment fails" << std::endl; 
        exit(EXIT_FAILURE); 
    }
    size_t sliced_giantstep_num = giantstep_num/THREAD_NUM; 


    ECPoint ecp_slicedrange = ecp_giantstep * BigInt(sliced_giantstep_num);

    /* begin to search */
    std::vector<size_t> i_index(THREAD_NUM); 
    std::vector<size_t> j_index(THREAD_NUM);

    // initialize searchpoint vector
    std::vector<ECPoint> ecp_vec_searchanchor(THREAD_NUM);
     
    ecp_vec_searchanchor[0] = h;
    for (auto i = 1; i < THREAD_NUM; i++){
        ecp_vec_searchanchor[i] = ecp_vec_searchanchor[i-1] + ecp_slicedrange;         
    }
    
    std::vector<int> finding(THREAD_NUM, 0); 
    int parallel_finding = 0; 

    // check if the hash map is empty
    if(int2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        exit (EXIT_FAILURE);
    }

    std::vector<std::thread> searchtask;
    for(auto i = 0; i < THREAD_NUM; i++){ 
        searchtask.push_back(std::thread(Search_Sliced_Range, std::ref(ecp_vec_searchanchor[i]), 
                             std::ref(ecp_giantstep), std::ref(sliced_giantstep_num), 
                             std::ref(i_index[i]), std::ref(j_index[i]), 
                             std::ref(finding[i]), std::ref(parallel_finding)));
    }

    for(auto i = 0; i < THREAD_NUM; i++){ 
        searchtask[i].join(); 
    }    

    BigInt bn_i, bn_j;


    for(auto i = 0; i < THREAD_NUM; i++)
    { 
        if(finding[i] == 1)
        {
            // x = i + j*giantstep_size; 
            x = BigInt(i_index[i]) + BigInt(j_index[i]+i*sliced_giantstep_num) * BigInt(babystep_num); 
            break;          
        }
    }  
    if (parallel_finding == 1) return true; 
    else return false; 
}


void BruteForce_DLOG(const ECPoint &g, const ECPoint &h, BigInt &x)
{
    x = bn_0;
    ECPoint ecp_try = g * x;  
    while(ecp_try != h){
        ecp_try = ecp_try + g; 
        x = x + bn_1;
    }
} 

# endif