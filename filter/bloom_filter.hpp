/*
Modified from https://github.com/ArashPartow/bloom
(1) simplify the design
(2) add serialize/deserialize interfaces
*/

#ifndef KUNLUN_BLOOM_FILTER_HPP
#define KUNLUN_BLOOM_FILTER_HPP


#include "../include/std.inc"
#include "../crypto/ec_point.hpp"
#include "../utility/murmurhash3.hpp"

//00000001 00000010 00000100 00001000 00010000 00100000 01000000 10000000
static const uint8_t bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};


/*
  Note:A distinct hash function need not be implementation-wise distinct. 
  In the current implementation "seeding" a common hash function with different values seems to be adequate.
*/

template<typename uint_type >
std::vector<uint_type> GenUniqueSaltVector(uint_type hash_num, uint_type random_seed)
{
   const uint_type predefined_salt_num = 128;
   static const uint_type predefined_salt[predefined_salt_num] = {
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

   std::vector<uint_type> vec_salt; 
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
         uint_type current_salt = static_cast<uint_type>(rand()) * static_cast<uint_type>(rand());
         if (0 == current_salt) continue;
         if (vec_salt.end() == std::find(vec_salt.begin(), vec_salt.end(), current_salt)){
            vec_salt.emplace_back(current_salt);
         }
      }
   }

   return vec_salt; 
}

template <typename uint_type>
inline uint_type AdhocHash(uint_type salt, const unsigned char* input, size_t LEN)
{
   uint_type digest = salt; 
   const unsigned char* itr = input;
   uint_type loop = 0;
   size_t REMAINING_LEN = LEN; 
   uint32_t a, b, c;
   uint16_t d; 
   uint8_t e; 
   while (REMAINING_LEN >= 8){
      a = *(reinterpret_cast<const uint32_t*>(itr)); itr += 4;
      b = *(reinterpret_cast<const uint32_t*>(itr)); itr += 4;
      digest ^= (digest << 7) ^ a * (digest >> 3) ^ (~((digest << 11) + (b ^ (digest >> 5))));
      REMAINING_LEN -= 8;
   }

   if (REMAINING_LEN >= 4){
      c = *(reinterpret_cast<const uint32_t*>(itr)); itr += 4;
      if (loop & 0x01) digest ^=  (digest << 7) ^ b * (digest >> 3);
      else digest ^= (~((digest << 11) + (c ^ (digest >> 5))));
      ++loop;
      REMAINING_LEN -= 4;
   }

   if (REMAINING_LEN >= 2){
      d = *(reinterpret_cast<const uint16_t*>(itr)); itr += 2;
      if (loop & 0x01) digest ^= (digest <<  7) ^  d * (digest >> 3);
      else digest ^= (~((digest << 11) + (d ^ (digest >> 5))));
      ++loop;
      REMAINING_LEN -= 2;  
   }

   if (REMAINING_LEN == 1){
      e = *(reinterpret_cast<const uint8_t*>(itr)); itr += 1;
      digest += (e ^ (digest * 0xA5A5A5A5)) + loop;
      REMAINING_LEN -= 1;  
   }
   
   return digest;
}

template <class uint_type>
class BloomFilter{
public:
   uint_type hash_num;  // k
   std::vector<uint_type> vec_salt;

   uint_type table_size; // m
   std::vector<uint8_t> bit_table;
    
   uint_type projected_element_num; // n
   uint_type random_seed;
   //double desired_false_positive_probability;
   size_t inserted_element_num;

   size_t object_size; // the storage size for serializing object


/*
  find the number of hash functions and minimum amount of storage bits required 
  to construct a bloom filter consistent with the user defined false positive probability
  and estimated element insertion num
*/
   BloomFilter() {}; 

   BloomFilter(size_t projected_element_num, double desired_false_positive_probability)
   {
      hash_num = static_cast<uint_type>(-log2(desired_false_positive_probability));
      random_seed = static_cast<uint_type>(0xA5A5A5A55A5A5A5A * 0xA5A5A5A5 + 1); 
      vec_salt = GenUniqueSaltVector(hash_num, random_seed);   
      table_size = static_cast<uint_type>(projected_element_num * (-1.44 * log2(desired_false_positive_probability)));
      bit_table.resize(table_size/8, static_cast<uint8_t>(0x00));
      
      inserted_element_num = 0; 

      object_size = 3 * sizeof(uint_type) + table_size/8;
   }

   ~BloomFilter() {}; 


   inline void insert(const uint8_t* input, size_t LEN)
   {
      size_t bit_index = 0;
      for (auto i = 0; i < hash_num; i++){
         bit_index = AdhocHash(vec_salt[i], input, LEN) % table_size;
         //bit_index = MurmurHash3(vec_salt[i], input, LEN) % table_size;
         bit_table[bit_index / 8] |= bit_mask[bit_index % 8];
      }
      inserted_element_num++;
   }

   template <typename T> // Note: T must be a C++ POD type.
   inline void insert(const T& t)
   {
      insert(reinterpret_cast<uint8_t*>(&t), sizeof(T));
   }

   inline void insert(const std::string& str)
   {
      insert(reinterpret_cast<const uint8_t*>(str.data()), str.size());
   }

   inline void insert(const ECPoint &A)
   {
      unsigned char buffer[POINT_BYTE_LEN]; 
      EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
      insert(reinterpret_cast<const uint8_t*>(buffer), POINT_BYTE_LEN);
   }

   inline void insert(const std::vector<ECPoint> &vec_A)
   {
      size_t num = vec_A.size();
      unsigned char *buffer = new unsigned char[num*POINT_BYTE_LEN]; 
      for(auto i = 0; i < num; i++){
         EC_POINT_point2oct(group, vec_A[i].point_ptr, POINT_CONVERSION_COMPRESSED, 
                            buffer+i*POINT_BYTE_LEN, POINT_BYTE_LEN, nullptr);
         insert(reinterpret_cast<const uint8_t*>(buffer+i*POINT_BYTE_LEN), POINT_BYTE_LEN);
      }
      delete[] buffer; 
   }

   inline void insert(const char* data, const std::size_t& LEN)
   {
      insert(reinterpret_cast<const uint8_t*>(data), LEN);
   }

   template <typename InputIterator>
   inline void insert(const InputIterator begin, const InputIterator end)
   {
      InputIterator itr = begin;

      while (end != itr)
      {
         insert(*(itr++));
      }
   }

   template <class T, class Allocator, template <class,class> class Container>
   inline void insert(Container<T, Allocator>& c)
   {
      #ifdef OMP
         #pragma omp parallel for
      #endif
      for(auto i = 0; i < c.size(); i++)
         insert(c[i]); 
   }

   inline bool contain(const uint8_t* input, size_t LEN) const
   {
      size_t bit_index = 0;
      size_t local_bit_index = 0; 
      for(auto i = 0; i < vec_salt.size(); i++)
      {
         bit_index = AdhocHash(vec_salt[i], input, LEN) % table_size; 
         //bit_index = MurmurHash3(vec_salt[i], input, LEN) % table_size;
         local_bit_index = bit_index % 8;
         if ((bit_table[bit_index/8] & bit_mask[local_bit_index]) != bit_mask[local_bit_index]) 
            return false;
      }
      return true;
   }

   template <typename T>
   inline bool contain(const T& t) const
   {
      return contain(reinterpret_cast<uint8_t*>(&t), sizeof(T));
   }

   inline bool contain(const std::string& str) const
   {
      return contain(reinterpret_cast<const uint8_t*>(str.data()), str.size());
   }

   inline bool contain(const ECPoint& A) const
   {
      unsigned char buffer[POINT_BYTE_LEN]; 
      EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
      return contain(reinterpret_cast<const uint8_t*>(buffer), POINT_BYTE_LEN);
   }

   inline bool contain(const char* data, size_t LEN) const
   {
      return contain(reinterpret_cast<const uint8_t*>(data), LEN);
   }

   inline void clear()
   {
      std::fill(bit_table.begin(), bit_table.end(), static_cast<uint8_t>(0x00));
      inserted_element_num = 0;
   }

   inline bool writeobject(std::string file_name)
   {
      std::ofstream fout; 
      fout.open(file_name, std::ios::binary); 
      if(!fout){
        std::cerr << file_name << " open error" << std::endl;
        return false; 
      }

      fout.write(reinterpret_cast<char *>(&hash_num), 8);
      fout.write(reinterpret_cast<char *>(&random_seed), 8);
      fout.write(reinterpret_cast<char *>(&table_size), 8); 
      fout.write(reinterpret_cast<char *>(bit_table.data()), table_size/8); 

      fout.close(); 

      #ifdef DEBUG
         std::cout << "'" <<file_name << "' size = " << object_size << " bytes" << std::endl;
      #endif

      return true; 
   } 

   inline bool readobject(std::string file_name)
   {
      std::ifstream fin; 
      fin.open(file_name, std::ios::binary); 
      if(!fin){
        std::cerr << file_name << " open error" << std::endl;
        return false; 
      }

      fin.read(reinterpret_cast<char *>(&hash_num), sizeof(hash_num));
      fin.read(reinterpret_cast<char *>(&random_seed), sizeof(random_seed)); 
      vec_salt = GenUniqueSaltVector(hash_num, random_seed); 
      fin.read(reinterpret_cast<char *>(&table_size), sizeof(table_size)); 
      bit_table.resize(table_size/8, static_cast<uint8_t>(0x00));
      fin.read(reinterpret_cast<char *>(bit_table.data()), table_size/8); 
      
      return true;
   } 


   inline bool writeobject(char* buffer)
   {
      if(buffer == nullptr){
         std::cerr << "allocate memory for bloom filter fails" << std::endl;
         return false; 
      }
      
      memcpy(buffer, &hash_num, sizeof(uint_type));
      memcpy(buffer+  sizeof(uint_type), &random_seed, sizeof(uint_type)); 
      memcpy(buffer+2*sizeof(uint_type), &table_size, sizeof(uint_type)); 
      memcpy(buffer+3*sizeof(uint_type), bit_table.data(), table_size/8); 

      return true; 
   } 

   inline bool readobject(char* buffer)
   {
      if(buffer == nullptr){
         std::cerr << "allocate memory for bloom filter fails" << std::endl;
         return false; 
      }

      memcpy(&hash_num, buffer, sizeof(uint_type));
      memcpy(&random_seed, buffer+sizeof(uint_type), sizeof(uint_type)); 
      vec_salt = GenUniqueSaltVector(hash_num, random_seed); 
      memcpy(&table_size, buffer+2*sizeof(uint_type), sizeof(uint_type)); 
      bit_table.resize(table_size/8, static_cast<uint8_t>(0x00));
      memcpy(bit_table.data(), buffer+3*sizeof(uint_type), table_size/8); 

      return true; 
   } 
}; 

  
#endif