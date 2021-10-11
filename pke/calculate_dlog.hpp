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
void BuildSlicedKeyTable(ECPoint &g, ECPoint &startpoint, size_t startindex, size_t SLICED_BABYSTEP_NUM, unsigned char* buffer)
{    
    size_t hashkey; 
    for(auto i = 0; i < SLICED_BABYSTEP_NUM; i++)
    {
        hashkey = std::hash<std::string>{}(startpoint.ThreadSafeToByteString()); 
        std::memcpy(buffer+(startindex+i)*INT_BYTE_LEN, &hashkey, INT_BYTE_LEN);
        startpoint = startpoint.ThreadSafeAdd(g); 
    } 
}


/* 
* generate babystep hashkey table
* standard method is using babystep point as key for point2index hashmap: big key size
* to shorten key size, use hash to map babystep point to unique key
*/

void ParallelBuildSerializeKeyTable(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM, 
                                    size_t DEC_THREAD_NUM, std::string keytable_filename)
{
    std::cout << "babystep hashkey table does not exist, begin to build and serialize >>>" << std::endl;

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep num = giantstep size

    if (BABYSTEP_NUM%DEC_THREAD_NUM != 0)
    {
        std::cout << "thread assignment fails" << std::endl; 
        exit(EXIT_FAILURE); 
    }
    size_t SLICED_BABYSTEP_NUM = BABYSTEP_NUM/DEC_THREAD_NUM; 

    std::vector<ECPoint> startpoint(DEC_THREAD_NUM); 
    std::vector<size_t> startindex(DEC_THREAD_NUM); 

    //#pragma omp parallel// NEW ADD
    for (auto i = 0; i < DEC_THREAD_NUM; i++){
        startindex[i] = i * SLICED_BABYSTEP_NUM; 
        startpoint[i] = g * BigInt(startindex[i]);
    } 

    // allocate memory
    unsigned char *buffer = new unsigned char[BABYSTEP_NUM*INT_BYTE_LEN]();
    if(buffer == nullptr)
    {
        std::cerr << "fail to create buffer for babystep table" << std::endl; 
        exit(EXIT_FAILURE); 
    } 

    std::vector<std::thread> build_task;
    for(auto i = 0; i < DEC_THREAD_NUM; i++){ 
        build_task.push_back(std::thread(BuildSlicedKeyTable, std::ref(g), std::ref(startpoint[i]), 
                             std::ref(startindex[i]), std::ref(SLICED_BABYSTEP_NUM), std::ref(buffer)));
    }

    for(auto i = 0; i < DEC_THREAD_NUM; i++){ 
        build_task[i].join(); 
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
    fout.write(reinterpret_cast<char *>(buffer), BABYSTEP_NUM*INT_BYTE_LEN); 
    fout.close(); 
    delete[] buffer; 
        
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "serializing babystep table takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}


void BuildSerializeKeyTable(ECPoint &g, size_t RANGE_LEN, size_t TRADEOFF_NUM, std::string keytable_filename)
{
    std::cout << "babystep hashkey table does not exist, begin to build and serialize >>>" << std::endl;

    auto start_time = std::chrono::steady_clock::now(); // start to count the time
    size_t BABYSTEP_NUM = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep num = giantstep size

    // allocate memory
    unsigned char *buffer = new unsigned char[BABYSTEP_NUM*INT_BYTE_LEN]();
    if(buffer == nullptr)
    {
        std::cerr << "fail to create buffer for babystep table" << std::endl; 
        exit(EXIT_FAILURE); 
    } 

    size_t hashkey; 
    ECPoint startpoint = GetPointAtInfinity();  
    for(auto index = 0; index < BABYSTEP_NUM; index++)
    {
        hashkey = std::hash<std::string>{}(startpoint.ToByteString()); 
        std::memcpy(buffer+index*INT_BYTE_LEN, &hashkey, INT_BYTE_LEN);
        startpoint = startpoint + g; 
    } 

    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "building babystep hashkey table takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;  

    start_time = std::chrono::steady_clock::now(); // end to count the time
    // save buffer to babystep table
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
        
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "serializing babystep table takes time = " 
        << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
}

/* deserialize keytable and build hashmap */
void DeserializeKeyTableBuildHashMap(std::string keytable_filename, size_t RANGE_LEN, size_t TRADEOFF_NUM)
{   
    std::cout << "babystep table already exists, begin to load and build the hashmap >>>" << std::endl; 

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

    std::cout << keytable_filename << " size = " << FILE_BYTE_LEN/pow(2,20) << " MB" << std::endl;

    fin.seekg(0);                  // reset the file pointer to the beginning of file
    fin.read(reinterpret_cast<char*>(buffer), FILE_BYTE_LEN); // read file from disk to RAM
    fin.close(); 
    auto end_time = std::chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    std::cout << "deserializing babystep table takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    // construct hashmap from buffer 
    start_time = std::chrono::steady_clock::now(); // start to count the time
    std::size_t hashkey; 


    /* point_to_index_map[ECn_to_String(babystep)] = i */
    for(auto i = 0; i < BABYSTEP_NUM; i++)
    {
        std::memcpy(&hashkey, buffer+i*INT_BYTE_LEN, INT_BYTE_LEN);
        int2index_map[hashkey] = i; 
    }

    delete[] buffer; 
    
    end_time = std::chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    std::cout << "building hashmap takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
} 


/* parallelizable search task */
void SearchSlicedRange(ECPoint &ecp_searchanchor, ECPoint &ecp_giantstep, size_t SLICED_GIANTSTEP_NUM, 
                       size_t &i, size_t &j, int &FIND, bool &PARALLEL_FIND)
{    
    std::size_t hashkey; 
    // giant-step and baby-step search
    for(j = 0; j < SLICED_GIANTSTEP_NUM; j++)
    {
        /* If key not found in map iterator to end is returned */ 
        if (PARALLEL_FIND == 1) break; 
        // map the point to keyvalue
        hashkey = std::hash<std::string>{}(ecp_searchanchor.ThreadSafeToByteString()); 
        
        // baby-step search in the hash map
        if (int2index_map.find(hashkey) == int2index_map.end())
        {
            //ecp_searchanchor = ecp_searchanchor + ecp_giantstep; // not found, take a giant-step forward   
            ecp_searchanchor = ecp_searchanchor.ThreadSafeAdd(ecp_giantstep); 
        }
        else{
            i = int2index_map[hashkey]; 
            FIND = 1; 
            PARALLEL_FIND = true; 
            break;
        }
    }
}


// compute x = log_g h
bool ParallelShanksDLOG(const ECPoint &g, const ECPoint &h, size_t RANGE_LEN, 
                        size_t TRADEOFF_NUM, size_t DEC_THREAD_NUM, BigInt &x)
{
    size_t BABYSTEP_NUM  = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep_num = giantstep_size
    size_t GIANTSTEP_NUM = pow(2, RANGE_LEN/2 - TRADEOFF_NUM); 

    /* compute the giantstep */
    ECPoint ecp_giantstep = g * BigInt(BABYSTEP_NUM); // set giantstep = g^babystep_num
    ecp_giantstep = ecp_giantstep.Invert();
 
    if(GIANTSTEP_NUM%DEC_THREAD_NUM != 0)
    {
        std::cerr << "thread assignment fails" << std::endl; 
        exit(EXIT_FAILURE); 
    }
    size_t SLICED_GIANTSTEP_NUM = GIANTSTEP_NUM/DEC_THREAD_NUM; 


    ECPoint ecp_slicedrange = ecp_giantstep * BigInt(SLICED_GIANTSTEP_NUM);

    /* begin to search */
    std::vector<size_t> i_index(DEC_THREAD_NUM); 
    std::vector<size_t> j_index(DEC_THREAD_NUM);

    // initialize searchpoint vector
    std::vector<ECPoint> ecp_vec_searchanchor(DEC_THREAD_NUM);
     
    ecp_vec_searchanchor[0] = h;
    for (auto i = 1; i < DEC_THREAD_NUM; i++){
        ecp_vec_searchanchor[i] = ecp_vec_searchanchor[i-1] + ecp_slicedrange;         
    }
    
    std::vector<int> FIND(DEC_THREAD_NUM, 0); 
    bool PARALLEL_FIND = false; 

    // check if the hash map is empty
    if(int2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        exit (EXIT_FAILURE);
    }

    std::vector<std::thread> search_task;
    for(auto i = 0; i < DEC_THREAD_NUM; i++){ 
        search_task.push_back(std::thread(SearchSlicedRange, std::ref(ecp_vec_searchanchor[i]), 
                             std::ref(ecp_giantstep), std::ref(SLICED_GIANTSTEP_NUM), 
                             std::ref(i_index[i]), std::ref(j_index[i]), 
                             std::ref(FIND[i]), std::ref(PARALLEL_FIND)));
    }

    for(auto i = 0; i < DEC_THREAD_NUM; i++){ 
        search_task[i].join(); 
    }    

    for(auto i = 0; i < DEC_THREAD_NUM; i++)
    { 
        if(FIND[i] == 1)
        {
            // x = i + j*giantstep_size; 
            x = BigInt(i_index[i]) + BigInt(j_index[i]+i*SLICED_GIANTSTEP_NUM) * BigInt(BABYSTEP_NUM); 
            break;          
        }
    }  
    if (PARALLEL_FIND == true) return true; 
    else return false; 
}


// compute x = log_g h
bool ShanksDLOG(const ECPoint &g, const ECPoint &h, size_t RANGE_LEN, size_t TRADEOFF_NUM, BigInt &x)
{
    size_t BABYSTEP_NUM  = pow(2, RANGE_LEN/2 + TRADEOFF_NUM); // babystep_num = giantstep_size
    size_t GIANTSTEP_NUM = pow(2, RANGE_LEN/2 - TRADEOFF_NUM); 

    /* compute the giantstep */
    ECPoint ecp_giantstep = g * BigInt(BABYSTEP_NUM); // set giantstep = g^babystep_num
    ecp_giantstep = ecp_giantstep.Invert();

    bool FIND = false; 

    // check if the hash map is empty
    if(int2index_map.empty() == true)
    {
        std::cout << "the hashmap is empty" << std::endl; 
        exit (EXIT_FAILURE);
    }

    std::size_t hashkey; 
    ECPoint ecp_startpoint = h;
    size_t i, j; 
    for(j = 0; j < GIANTSTEP_NUM; j++)
    {
        // map the point to keyvalue
        hashkey = std::hash<std::string>{}(ecp_startpoint.ToByteString()); 
        
        // baby-step search in the hash map
        if (int2index_map.find(hashkey) == int2index_map.end())
        {
            ecp_startpoint = ecp_startpoint + ecp_giantstep; // not found, take a giant-step forward   
        }
        else{
            i = int2index_map[hashkey]; 
            FIND = true;  
            break;
        }
    }
    
    x = BigInt(i) + BigInt(j) * BigInt(BABYSTEP_NUM); // x = i + j*giantstep_size; 
    
    return FIND;  
}

void BruteForceDLOG(const ECPoint &g, const ECPoint &h, BigInt &x)
{
    x = bn_0;
    ECPoint ecp_try = g * x;  
    while(ecp_try != h){
        ecp_try = ecp_try + g; 
        x = x + bn_1;
    }
} 

# endif