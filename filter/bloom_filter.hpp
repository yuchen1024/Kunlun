/*
** Modified from https://github.com/ArashPartow/bloom
** (1) simplify the design
** (2) add serialize/deserialize interfaces
*/

#ifndef KUNLUN_BLOOM_FILTER_HPP
#define KUNLUN_BLOOM_FILTER_HPP

#include "../include/std.inc"
#include "../utility/serialization.hpp"
#include "../crypto/ec_point.hpp" // cause we need to insert EC Point to filter
#include "../crypto/ec_25519.hpp"
#include "../utility/murmurhash3.hpp"

//00000001 00000010 00000100 00001000 00010000 00100000 01000000 10000000
inline const uint8_t bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

// selection of keyed hash for bloom filter
#define FastKeyedHash LiteMurmurHash // an alternative choice is MurmurHash3 

/*
  Note:A distinct hash function need not be implementation-wise distinct. 
  In the current implementation "seeding" a common hash function with different values seems to be adequate.
*/

std::vector<uint32_t> GenUniqueSaltVector(size_t hash_num, uint32_t random_seed){
   const size_t predefined_salt_num = 128;
   static const uint32_t predefined_salt[predefined_salt_num] = {
      0xAAAAAAAA, 0x55555555, 0x33333333, 0xCCCCCCCC, 0x66666666, 0x99999999, 0xB5B5B5B5, 0x4B4B4B4B,
      0xAA55AA55, 0x55335533, 0x33CC33CC, 0xCC66CC66, 0x66996699, 0x99B599B5, 0xB54BB54B, 0x4BAA4BAA,
      0xAA33AA33, 0x55CC55CC, 0x33663366, 0xCC99CC99, 0x66B566B5, 0x994B994B, 0xB5AAB5AA, 0xAAAAAA33,
      0x555555CC, 0x33333366, 0xCCCCCC99, 0x666666B5, 0x9999994B, 0xB5B5B5AA, 0xFFFFFFFF, 0xFFFF0000,
      0xB823D5EB, 0xC1191CDF, 0xF623AEB3, 0xDB58499F, 0xC8D42E70, 0xB173F616, 0xA91A5967, 0xDA427D63,
      0xB1E8A2EA, 0xF6C0D155, 0x4909FEA3, 0xA68CC6A7, 0xC395E782, 0xA26057EB, 0x0CD5DA28, 0x467C5492,
      0xF15E6982, 0x61C6FAD3, 0x9615E352, 0x6E9E355A, 0x689B563E, 0x0C9831A8, 0x6753C18B, 0xA622689B,
      0x8CA63C47, 0x42CC2884, 0x8E89919B, 0x6EDBD7D3, 0x15B6796C, 0x1D6FDFE4, 0x63FF9092, 0xE7401432,
      0xEFFE9412, 0xAEAEDF79, 0x9F245A31, 0x83C136FC, 0xC3DA4A8C, 0xA5112C8C, 0x5271F491, 0x9A948DAB,
      0xCEE59A8D, 0xB5F525AB, 0x59D13217, 0x24E7C331, 0x697C2103, 0x84B0A460, 0x86156DA9, 0xAEF2AC68,
      0x23243DA5, 0x3F649643, 0x5FA495A8, 0x67710DF8, 0x9A6C499E, 0xDCFB0227, 0x46A43433, 0x1832B07A,
      0xC46AFF3C, 0xB9C8FFF0, 0xC9500467, 0x34431BDF, 0xB652432B, 0xE367F12B, 0x427F4C1B, 0x224C006E,
      0x2E7E5A89, 0x96F99AA5, 0x0BEB452A, 0x2FD87C39, 0x74B2E1FB, 0x222EFD24, 0xF357F60C, 0x440FCB1E,
      0x8BBE030F, 0x6704DC29, 0x1144D12F, 0x948B1355, 0x6D8FD7E9, 0x1C11A014, 0xADD1592F, 0xFB3C712E,
      0xFC77642F, 0xF9C4CE8C, 0x31312FB9, 0x08B0DD79, 0x318FA6E7, 0xC040D23D, 0xC0589AA7, 0x0CA5C075,
      0xF874B172, 0x0CF914D5, 0x784D3280, 0x4E8CFEBC, 0xC569F575, 0xCDB2A091, 0x2CC016B4, 0x5C5F4421};

   std::vector<uint32_t> vec_salt; 
   if (hash_num <= predefined_salt_num){
      std::copy(predefined_salt, predefined_salt + hash_num, std::back_inserter(vec_salt));
      // integrate the user defined random seed to allow for the generation of unique bloom filter instances.
      for (auto i = 0; i < hash_num; i++){
         vec_salt[i] = vec_salt[i] * vec_salt[(i+3) % vec_salt.size()] + random_seed;
      }
   }
   else{
      std::copy(predefined_salt, predefined_salt + predefined_salt_num, std::back_inserter(vec_salt));
      srand(random_seed);
      while (vec_salt.size() < hash_num){
         uint32_t current_salt = rand() * rand();
         if (0 == current_salt) continue;
         if (vec_salt.end() == std::find(vec_salt.begin(), vec_salt.end(), current_salt)){
            vec_salt.emplace_back(current_salt);
         }
      }
   }

   return vec_salt; 
}

class BloomFilter{
public:
   uint32_t random_seed; // used to generate vec_salt
   uint32_t hash_num;  // number of keyed hash functions
   std::vector<uint32_t> vec_salt; // salt vector: size = hash_num

   // to change it uint64_t, you should also modify the range of hash
   uint32_t table_size; // m: bit length of bit_table
   std::vector<uint8_t> bit_table;
    
   size_t projected_element_num; // n
   size_t inserted_element_num;
/*
  find the number of hash functions and minimum amount of storage bits required 
  to construct a bloom filter consistent with the user defined false positive probability
  and estimated element insertion num
*/
BloomFilter() {}; 

BloomFilter(size_t max_element_num, size_t statistical_security_parameter)
{
   //desired_false_positive_probability = 1/2^{statistical_security_parameter};
   //hash_num = static_cast<size_t>(-log2(desired_false_positive_probability));
   hash_num = statistical_security_parameter; 
   random_seed = static_cast<uint32_t>(0xA5A5A5A55A5A5A5A * 0xA5A5A5A5 + 1); 
   vec_salt = GenUniqueSaltVector(hash_num, random_seed);   
   //table_size = static_cast<uint32_t>(max_element_num * (-1.44 * log2(desired_false_positive_probability)));
   table_size = static_cast<uint32_t>(max_element_num * (1.44 * statistical_security_parameter));
   // the following operation is very important => make table size = 8*n 
   table_size = ((table_size+0x07) >> 3) << 3; // (table_size+7)/8*8

   bit_table.resize(table_size/8, static_cast<uint8_t>(0x00)); // naive implementation
   projected_element_num = max_element_num;
   inserted_element_num = 0; 
}

~BloomFilter() {}; 

size_t ObjectSize()
{
   /* 
   ** hash_num + random_seed + table_size + projected_element_num + inserted_element_num + table_content
   ** one can derive vec_salt from random_seed, so there is no need to save them
   */
   return 3 * sizeof(uint32_t) + 2 * sizeof(size_t) + table_size/8;
}


inline void PlainInsert(const void* input, size_t LEN)
{
   size_t bit_index[hash_num];

   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for (auto i = 0; i < hash_num; i++){
      bit_index[i] = FastKeyedHash(vec_salt[i], input, LEN) % table_size;    
      #pragma omp atomic // atomic operation
      bit_table[bit_index[i] >> 3] |= bit_mask[bit_index[i] & 0x07]; 
   }
   #pragma omp atomic
   inserted_element_num++;
}

template <typename ElementType> // Note: T must be a C++ POD type.
inline void Insert(const ElementType& element)
{
   PlainInsert(&element, sizeof(ElementType));
}

// specialize for string
#ifdef IS_MACOS
template <> 
#endif
inline void Insert(const std::string& str)
{
   PlainInsert(str.data(), str.size());
}

/*
** You can insert any custom-type data you like as below
*/
// specialize for ECPoint
#ifdef IS_MACOS
template <> 
#endif
inline void Insert(const ECPoint &A)
{
   int thread_num = omp_get_thread_num();
   #ifdef ECPOINT_COMPRESSED
      unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
      memset(buffer, 0, POINT_COMPRESSED_BYTE_LEN);  
      EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
      PlainInsert(buffer, POINT_COMPRESSED_BYTE_LEN);
   #else
      unsigned char buffer[POINT_BYTE_LEN]; 
      memset(buffer, 0, POINT_BYTE_LEN); 
      EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, bn_ctx[thread_num]);
      PlainInsert(buffer, POINT_BYTE_LEN);
   #endif
}

template <typename InputIterator>
inline void Insert(const InputIterator begin, const InputIterator end)
{
   InputIterator itr = begin;
   while (end != itr)
   {
      Insert(*(itr++));
   }
}

template <class T, class Allocator, template <class,class> class Container>
inline void Insert(const Container<T, Allocator>& container)
{
   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < container.size(); i++){
      Insert(container[i]); 
   }
}

// specialize for vector<ECPoint>
#ifdef IS_MACOS
template <> 
#endif
inline void Insert(const std::vector<ECPoint> &vec_A)
{   
   //sequential implementation
   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < vec_A.size(); i++){
      Insert(vec_A[i]); 
   }
}


inline bool PlainContain(const void* input, size_t LEN) const
{
   bool CONTAIN = true; // assume input in filter at the beginning
   std::vector<size_t> bit_index(hash_num);
   std::vector<size_t> local_bit_index(hash_num); 
   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < hash_num; i++)
   {
      if(CONTAIN == true)
      {
         bit_index[i] = FastKeyedHash(vec_salt[i], input, LEN) % table_size; 
         local_bit_index[i] = bit_index[i] & 0x07;  // bit_index mod 8
         if ((bit_table[bit_index[i] >> 3] & bit_mask[local_bit_index[i]]) != bit_mask[local_bit_index[i]])
         { 
            CONTAIN  = false;
         }
      }
   }
   return CONTAIN;
}

template <typename ElementType>
inline bool Contain(const ElementType& element) const
{
   return PlainContain(&element, sizeof(ElementType));
}

inline bool Contain(const std::string& str) const
{
   return PlainContain(str.data(), str.size());
}

// specialize for ECPoint
#ifdef IS_MACOS
template <> 
#endif
inline bool Contain(const ECPoint& A) const
{
   int thread_num = omp_get_thread_num();
   #ifdef ECPOINT_COMPRESSED
      unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
      memset(buffer, 0, POINT_COMPRESSED_BYTE_LEN);  
      EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_COMPRESSED_BYTE_LEN, bn_ctx[thread_num]);
      return PlainContain(buffer, POINT_COMPRESSED_BYTE_LEN);
   #else
      unsigned char buffer[POINT_BYTE_LEN];
      memset(buffer, 0, POINT_BYTE_LEN);  
      EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, bn_ctx[thread_num]);
      return PlainContain(buffer, POINT_BYTE_LEN);
   #endif
}



template <class T, class Allocator, template <class,class> class Container>
inline std::vector<uint8_t> Contain(const Container<T, Allocator>& container) const
{
   size_t LEN = container.size();
   std::vector<uint8_t> vec_indication_bit(LEN); 
   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < container.size(); i++){
      if(Contain(container[i]) == true) vec_indication_bit[i] = 1;
      else vec_indication_bit[i] = 0; 
   }
   return vec_indication_bit; 
}


// specialize for vector<ECPoint>
#ifdef IS_MACOS
template <> 
#endif
inline std::vector<uint8_t> Contain(const std::vector<ECPoint> &vec_A) const
{
   size_t LEN = vec_A.size();
   std::vector<uint8_t> vec_indication_bit(LEN); 

   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < vec_A.size(); i++){
      if(Contain(vec_A[i]) == true) vec_indication_bit[i] = 1;
      else vec_indication_bit[i] = 0; 
   }
   return vec_indication_bit; 
}


/////////////////////////////////////////////////////////////////
/* specialize for curve 25519*/

// specialize for EC25519Point
#ifdef IS_MACOS
template <> 
#endif
inline void Insert(const EC25519Point &A)
{
   PlainInsert(A.px, 32);
}


// specialize for vector<EC25519Point>
#ifdef IS_MACOS
template <> 
#endif
inline void Insert(const std::vector<EC25519Point> &vec_A)
{   
   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < vec_A.size(); i++){
      Insert(vec_A[i]); 
   }
}

// specialize for EC25519Point
#ifdef IS_MACOS
template <> 
#endif
inline bool Contain(const EC25519Point& A) const
{
   return PlainContain(A.px, 32);
}

// specialize for vector<ECPoint>
#ifdef IS_MACOS
template <> 
#endif
inline std::vector<uint8_t> Contain(const std::vector<EC25519Point> &vec_A) const
{
   size_t LEN = vec_A.size();
   std::vector<uint8_t> vec_indication_bit(LEN); 

   #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
   for(auto i = 0; i < vec_A.size(); i++){
      if(Contain(vec_A[i]) == true) vec_indication_bit[i] = 1;
      else vec_indication_bit[i] = 0; 
   }
   return vec_indication_bit; 
}

///////////////////////////////////////////////////////////////////////////

inline void Clear()
{
   std::fill(bit_table.begin(), bit_table.end(), static_cast<uint8_t>(0x00));
   inserted_element_num = 0;
}
   
// write object to file
inline bool WriteObject(std::string file_name)
{
   std::ofstream fout; 
   fout.open(file_name, std::ios::binary); 
   if(!fout){
      std::cerr << file_name << " open error" << std::endl;
      return false; 
   }

   fout << random_seed; 
   fout << hash_num;
   fout << table_size; 
   fout << projected_element_num;
   fout << inserted_element_num;  
   fout << bit_table; 

   fout.close(); 

   #ifdef DEBUG
      std::cout << "'" <<file_name << "' size = " << ObjectSize() << " bytes" << std::endl;
   #endif

   return true; 
} 
   
// read object from file (reconstruct)
inline bool ReadObject(std::string file_name)
{
   std::ifstream fin; 
   fin.open(file_name, std::ios::binary); 
   if(!fin){
      std::cerr << file_name << " open error" << std::endl;
      return false; 
   }
   
   fin >> random_seed; 
   fin >> hash_num;    
   fin >> table_size;
   fin >> projected_element_num; 
   fin >> inserted_element_num;  
   
   // re-produce vec_salt
   vec_salt = GenUniqueSaltVector(hash_num, random_seed); 
   // re-build bit_table
   bit_table.resize(table_size/8, static_cast<uint8_t>(0x00));
   fin >> bit_table;
   // fin.read(reinterpret_cast<char *>(bit_table.data()), table_size/8); 
      
   return true;
} 

// write object to buffer
inline bool WriteObject(char* buffer)
{
   if(buffer == nullptr){
      std::cerr << "allocate memory for bloom filter fails" << std::endl;
      return false; 
   }
   size_t offset = 0; 
      
   memcpy(buffer + offset, &random_seed, sizeof(uint32_t));
   offset += sizeof(uint32_t);     
      
   memcpy(buffer + offset, &hash_num, sizeof(uint32_t));
   offset += sizeof(uint32_t);

   memcpy(buffer + offset, &table_size, sizeof(uint32_t));
   offset += sizeof(uint32_t);

   memcpy(buffer + offset, &projected_element_num, sizeof(size_t));
   offset += sizeof(size_t);

   memcpy(buffer + offset, &inserted_element_num, sizeof(size_t));
   offset += sizeof(size_t);
      
   memcpy(buffer + offset, bit_table.data(), table_size/8); 

   return true; 
} 

// read object from buffer
inline bool ReadObject(char* buffer)
{
   if(buffer == nullptr){
      std::cerr << "allocate memory for bloom filter fails" << std::endl;
      return false; 
   }

   size_t offset = 0; 
      
   memcpy(&random_seed, buffer + offset, sizeof(uint32_t));
   offset += sizeof(uint32_t);     
      
   memcpy(&hash_num, buffer + offset, sizeof(uint32_t));
   offset += sizeof(uint32_t);

   memcpy(&table_size, buffer + offset, sizeof(uint32_t));
   offset += sizeof(uint32_t);

   memcpy(&projected_element_num, buffer + offset, sizeof(size_t));
   offset += sizeof(size_t);

   memcpy(&inserted_element_num, buffer + offset, sizeof(size_t));
   offset += sizeof(size_t);

   // re-produce vec_salt
   vec_salt = GenUniqueSaltVector(hash_num, random_seed); 
      
   // re-build bit_table
   bit_table.resize(table_size/8, static_cast<uint8_t>(0x00));      
   memcpy(bit_table.data(), buffer + offset, table_size/8); 

   return true; 
} 

void PrintInfo() const{
   PrintSplitLine('-');
   std::cout << "BloomFilter Status:" << std::endl;
   std::cout << "inserted element num = " << inserted_element_num << std::endl;
   std::cout << "hashtable size = " << (bit_table.size() >> 10) << " KB\n" << std::endl;
   std::cout << "bits per element = " << double(bit_table.size()) * 8 / inserted_element_num << std::endl;
   PrintSplitLine('-');
}

}; 

  
#endif