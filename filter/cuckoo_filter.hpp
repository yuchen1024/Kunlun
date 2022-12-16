/*
** Modified from https://github.com/efficient/cuckoofilter
** (1) simplify the design
** (2) add serialize/deserialize interfaces
** Thanks discussions with Minglang Dong
*/

#ifndef KUNLUN_CUCKOO_FILTER_HPP
#define KUNLUN_CUCKOO_FILTER_HPP

#include "../include/std.inc"
#include "../utility/murmurhash3.hpp"
#include "../utility/bit_operation.hpp"
#include "../crypto/ec_point.hpp"


// selection of keyed hash for cuckoo filter
#define FastHash LiteMurmurHash 

enum InsertToBucketStatus {
    SuccessAndNoKick = 0,
    FreshInsertFailure = 1,
    SuccessButKick = 2,
};

struct VictimCache{
    uint32_t bucket_index;
    uint32_t tag;
    uint32_t used; // false or true
};

// Cuckoo filter interfaces: Insert, Delete, Contain. 
class CuckooFilter{
public:
    // Storage of items
    std::vector<uint8_t> bucket_table;

    // number of inserted elements
    size_t inserted_element_num; 

    size_t max_kick_count = 500; // maximum number of cuckoo kicks before claiming failure
    size_t slot_num = 4; // the slot num of each bucket
    size_t tag_bit_size = 16; 
    size_t bucket_byte_size; 
    size_t bucket_num; 

    VictimCache victim;

    CuckooFilter() {}; 

    CuckooFilter(size_t projected_element_num, double desired_false_positive_probability){
        max_kick_count = 500;
        slot_num = 4; 
        tag_bit_size = 16; 
        bucket_byte_size = slot_num * tag_bit_size / 8;

        // bucket_num must be always a power of two
        bucket_num = upperpower2(std::max<uint32_t>(1, projected_element_num /slot_num));
       
        double load_factor = (double)projected_element_num / (bucket_num * slot_num);
        if (load_factor > 0.96) {
            bucket_num = bucket_num * 2;
        }

        bucket_table.resize(bucket_num * slot_num * tag_bit_size / 8);
        memset(bucket_table.data(), 0, bucket_table.size()); 

        inserted_element_num = 0; 

        victim.used = 0;
    }

    ~CuckooFilter() {}


    size_t ObjectSize()
    {
        // hash_num + random_seed + table_size + table_content
        return 6 * 8 + bucket_table.size() + 4 * 3;
    }

    // index_1 = LEFT(Hash(x)) mod bucket_num serve as the first choice 
    inline uint32_t ComputeBucketIndex(uint32_t hash_value) {
        // since bucket_num = 2^n, the following is equivalent to hash_value mod 2^n
        return hash_value & (bucket_num - 1); // fetch left 32 bit
    }

    inline uint32_t ComputeTag(uint32_t hash_value) {
        uint32_t tag;
        // set tag as the leftmost "tag_bit_size" part 
        tag = hash_value >> (32 - tag_bit_size);
        tag += (tag == 0); // ensure tag is not zero
        return tag;
    }

    inline uint32_t ComputeAnotherBucketIndex(const uint32_t bucket_index, const uint32_t tag) {
        // index_2 = (index_1 XOR tag) mod bucket_num 
        return (bucket_index ^ (tag * 0x5bd1e995)) & (bucket_num - 1);
        //return (bucket_index ^ FastHash(&tag, 4)) & (bucket_num - 1);
    }

    // Insert an item to the filter.
    // To make this procedure efficient, we omit the repetetion check
    // so, we need to ensure the inserted element
    // We also omit extra check when victim is being used
    // simply presume in that case the filter will be very dense

    bool PlainInsert(const void* input, size_t LEN){
        if (victim.used){
            std::cerr << "there is not enough space" << std::endl;
            return false;
        }

        uint32_t hash_value = FastHash(fixed_salt32, input, LEN);
        uint32_t current_bucket_index = ComputeBucketIndex(hash_value); 
        uint32_t current_tag = ComputeTag(hash_value); 

        // std::cout << "bucket index = " << std::hex << current_bucket_index << std::endl;
        // std::cout << "tag = " << std::hex << current_tag << std::endl; 
        
        uint32_t kickout_tag = 0; 

        bool licence_to_kickout = false;
        size_t kick_count = 0;
        int insert_to_bucket_status;
        while (kick_count < max_kick_count) {
            insert_to_bucket_status = InsertTagToBucket(current_bucket_index, current_tag, licence_to_kickout, kickout_tag); 
            switch(insert_to_bucket_status){ 
                case SuccessAndNoKick: inserted_element_num++; return true;
                case FreshInsertFailure: licence_to_kickout = true; break;
                case SuccessButKick: kick_count++; current_tag = kickout_tag; break;
            }
            current_bucket_index = ComputeAnotherBucketIndex(current_bucket_index, current_tag);
        }
        // if there is still kickout tag after MaxKickCount times kick, save it to victim cache
        victim.bucket_index = current_bucket_index;
        victim.tag   = current_tag;
        victim.used  = 1;
        
        return true;
    }

    template <typename ElementType> // Note: T must be a C++ POD type.
    inline bool Insert(const ElementType& element)
    {
        return PlainInsert(&element, sizeof(ElementType));
    }

    inline bool Insert(const std::string& str)
    {
        return PlainInsert(str.data(), str.size());
    }

    // You can insert any custom-type data you like as below
    inline bool Insert(const ECPoint &A)
    {
        unsigned char buffer[POINT_BYTE_LEN]; 
        EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
        return PlainInsert(buffer, POINT_BYTE_LEN);
    }

    inline bool Insert(const std::vector<ECPoint> &vec_A)
    {
        bool insert_status = true; 

        size_t num = vec_A.size();
        unsigned char *buffer = new unsigned char[num*POINT_BYTE_LEN]; 
        for(auto i = 0; i < num; i++){
            EC_POINT_point2oct(group, vec_A[i].point_ptr, POINT_CONVERSION_COMPRESSED, 
                               buffer+i*POINT_BYTE_LEN, POINT_BYTE_LEN, nullptr);
            if(PlainInsert(buffer+i*POINT_BYTE_LEN, POINT_BYTE_LEN) == false){
                insert_status = false; break;
            } 
        }
        delete[] buffer; 
        return insert_status; 
    }

    template <typename InputIterator>
    inline bool Insert(const InputIterator begin, const InputIterator end)
    {
        bool insert_status = true; 
        InputIterator itr = begin;
        while (end != itr){   
            if(Insert(*(itr++)) == false){
                insert_status = false; break;
            }
        }
        return insert_status; 
    }

    template <class T, class Allocator, template <class,class> class Container>
    inline bool Insert(Container<T, Allocator>& container)
    {
        bool insert_status = true; 
        for(auto i = 0; i < container.size(); i++){
            if(Insert(container[i]) == false){
                insert_status = false; 
                std::cout << "insert the " << i << "-th element fails" << std::endl;
                break;
            }
        }
        return insert_status; 
    }

    // Report if the item is inserted, with false positive rate.
    bool PlainContain(const void* input, size_t LEN) {
        uint32_t hash_value = FastHash(fixed_salt32, input, LEN);
        uint32_t index1 = ComputeBucketIndex(hash_value); 
        uint32_t tag = ComputeTag(hash_value); 
        uint32_t index2 = ComputeAnotherBucketIndex(index1, tag);

        // check if find in buckets
        if (FindTagInBucket(index1, tag)) return true; 
        if (FindTagInBucket(index2, tag)) return true; 
        // check if in victim.cache
        if (victim.used && (tag == victim.tag) && (index1 == victim.bucket_index || index2 == victim.bucket_index)) return true; 
        return false;
    }

    template <typename ElementType>
    inline bool Contain(const ElementType& element) 
    {
        return PlainContain(&element, sizeof(ElementType));
    }

    inline bool Contain(const std::string& str) 
    {
        return PlainContain(str.data(), str.size());
    }

    inline bool Contain(const ECPoint& A) 
    {
        unsigned char buffer[POINT_BYTE_LEN]; 
        EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
        return PlainContain(buffer, POINT_BYTE_LEN);
    }


    bool TrySaveVictim(uint32_t bucket_index, uint32_t slot_index, uint32_t tag)
    {
        if (victim.used && (victim.bucket_index == bucket_index) && (victim.tag == tag))
        {
            victim.used = 0;
            WriteTag(bucket_index, slot_index, tag); 
            return true;
        }
        return false;
    }

    // Delete an key from the filter
    bool PlainDelete(const void* input, size_t LEN) {
        bool delete_status = false; 
        uint32_t hash_value = FastHash(fixed_salt32, input, LEN);
        uint32_t index1 = ComputeBucketIndex(hash_value); 
        uint32_t tag = ComputeTag(hash_value); 
        uint32_t index2 = ComputeAnotherBucketIndex(index1, tag);

        uint32_t delete_slot_index; 

        if (DeleteTagFromBucket(index1, tag, delete_slot_index)) {
            inserted_element_num--;
            delete_status = true;
            TrySaveVictim(index1, delete_slot_index, tag);
        }
    
        if (DeleteTagFromBucket(index2, tag, delete_slot_index)) {
            inserted_element_num--;
            delete_status = true;
            TrySaveVictim(index2, delete_slot_index, tag);
        } 
    
        if (victim.used && tag == victim.tag && (index1 == victim.bucket_index || index2 == victim.bucket_index)) {
            victim.used = 0;
            delete_status = true;
        }
    
        return delete_status; 
    }

    template <typename ElementType>
    inline bool Delete(const ElementType& element) 
    {
        return PlainDelete(&element, sizeof(ElementType));
    }

    inline bool Delete(const std::string& str) 
    {
        return PlainDelete(str.data(), str.size());
    }

    inline bool Delete(const ECPoint& A) 
    {
        unsigned char buffer[POINT_BYTE_LEN]; 
        EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
        return PlainDelete(buffer, POINT_BYTE_LEN);
    }

    // read tag from i-th bucket j-th slot
    inline uint32_t ReadTag(const size_t bucket_index, const size_t slot_index) 
    {
        const uint8_t* ptr = bucket_table.data() + bucket_index * bucket_byte_size;
        uint32_t tag;
        /* following code only works for little-endian */
        switch(tag_bit_size){
            case  8: tag = ptr[slot_index]; break;
            case 16: ptr += (slot_index << 1); tag = *((uint16_t*)ptr); break;
            case 32: tag = ((uint32_t*)ptr)[slot_index]; break;
        }
        return tag;
    }

    // write tag to pos(i,j)
    inline void WriteTag(const size_t bucket_index, const size_t slot_index, const uint32_t tag) 
    {
        const uint8_t *ptr = bucket_table.data() + bucket_index * bucket_byte_size;
        /* following code only works for little-endian */
        switch(tag_bit_size){
            case  8: ((uint8_t *)ptr)[slot_index] = tag; break; 
            case 16: ((uint16_t *)ptr)[slot_index] = tag; break; 
            case 32: ((uint32_t *)ptr)[slot_index] = tag; break;
        }
    }


    inline bool FindTagInBucket(const size_t bucket_index, const uint32_t tag) 
    {
        // caution: unaligned access & assuming little endian
        const uint8_t *ptr = bucket_table.data() + bucket_index * bucket_byte_size;
        uint64_t v; 
        switch(tag_bit_size){
            case  8: v = *(uint32_t*)ptr; return hasvalue8(v, tag);
            case 16: v = *(uint64_t*)ptr; return hasvalue16(v, tag);
            default:
                for (auto slot_index = 0; slot_index < slot_num; slot_index++) {
                    if (ReadTag(bucket_index, slot_index) == tag) return true;
                }
        }
        return false;
    }

    inline bool DeleteTagFromBucket(const size_t bucket_index, const uint32_t tag, uint32_t &delete_slot_index) {
        for (auto slot_index = 0; slot_index < slot_num; slot_index++) {
            if (ReadTag(bucket_index, slot_index) == tag) {
                WriteTag(bucket_index, slot_index, 0);
                delete_slot_index = slot_index; 
                return true;
            }
        }
        return false;
    }

    inline InsertToBucketStatus InsertTagToBucket(const size_t bucket_index, const uint32_t tag,
                                  const bool licence_to_kickout, uint32_t &kickout_tag) {

        for (auto slot_index = 0; slot_index < slot_num; slot_index++) {
            if (ReadTag(bucket_index, slot_index) == 0) {
                WriteTag(bucket_index, slot_index, tag);
                return SuccessAndNoKick;
            }
        }
        // licence_to_kickout = true indicates the element must be add to this bucket
        // licence_to_kickout = false indicates this is a new element, and can be add to the alternative bucket 

        if (licence_to_kickout == true) {
            size_t r = rand() % slot_num;
            kickout_tag = ReadTag(bucket_index, r);
            WriteTag(bucket_index, r, tag);
            return SuccessButKick; 
        }

        // here, we must have licence_to_kickout == false 
        return FreshInsertFailure;
    }

    inline bool WriteObject(std::string file_name){
        std::ofstream fout; 
        fout.open(file_name, std::ios::binary); 
        if(!fout){
            std::cerr << file_name << " open error" << std::endl;
            return false; 
        }

        fout << inserted_element_num;
        fout << max_kick_count;
        fout << slot_num;
        fout << tag_bit_size;
        fout << bucket_byte_size;
        fout << bucket_num;

        fout << victim.bucket_index;
        fout << victim.tag;
        fout << victim.used;

        fout << bucket_table; 

        fout.close(); 

        #ifdef DEBUG
            std::cout << "'" <<file_name << "' size = " << ObjectSize() << " bytes" << std::endl;
        #endif

      return true; 
   } 

   inline bool ReadObject(std::string file_name){
        std::ifstream fin; 
        fin.open(file_name, std::ios::binary); 
        if(!fin){
            std::cerr << file_name << " open error" << std::endl;
            return false; 
        }

        fin >> inserted_element_num;
        fin >> max_kick_count;
        fin >> slot_num;
        fin >> tag_bit_size;
        fin >> bucket_byte_size;
        fin >> bucket_num;

        fin >> victim.bucket_index;
        fin >> victim.tag;
        fin >> victim.used;

        bucket_table.resize(bucket_byte_size * bucket_num, static_cast<uint8_t>(0x00));
        fin >> bucket_table.data(); 
      
        return true;
   } 


   inline bool WriteObject(char* buffer){
        if(buffer == nullptr){
            std::cerr << "allocate memory for cuckoo filter fails" << std::endl;
            return false; 
        }

        memcpy(buffer,    &inserted_element_num, 8);
        memcpy(buffer+8,  &max_kick_count, 8);
        memcpy(buffer+16, &slot_num, 8);
        memcpy(buffer+24, &tag_bit_size, 8);
        memcpy(buffer+32, &bucket_byte_size, 8);
        memcpy(buffer+40, &bucket_num, 8);

        memcpy(buffer+48, &victim.bucket_index, 4);
        memcpy(buffer+52, &victim.tag, 4);
        memcpy(buffer+66, &victim.used, 4);
      
        memcpy(buffer+60, bucket_table.data(), bucket_table.size()); 

        return true; 
   } 

   inline bool ReadObject(char* buffer){
        if(buffer == nullptr){
            std::cerr << "allocate memory for cuckoo filter fails" << std::endl;
            return false; 
        }

        memcpy(&inserted_element_num, buffer, 8);
        memcpy(&max_kick_count, buffer+8, 8);
        memcpy(&slot_num, buffer+16, 8);
        memcpy(&tag_bit_size, buffer+24, 8);
        memcpy(&bucket_byte_size, buffer+32, 8);
        memcpy(&bucket_num, buffer+40, 8);
        
        memcpy(&victim.bucket_index, buffer+48, 4);
        memcpy(&victim.tag, buffer+52, 4);
        memcpy(&victim.used, buffer+56, 4);

        bucket_table.resize(bucket_byte_size * bucket_num, static_cast<uint8_t>(0x00));
        memcpy(bucket_table.data(), buffer+60, bucket_table.size()); 

        return true; 
   } 


    /* methods for providing stats  */
    void PrintInfo() {
        PrintSplitLine('-');
        std::cout << "CuckooFilter Status:" << std::endl;
        std::cout << "inserted element num = " << inserted_element_num << std::endl;
        std::cout << "load factor = " << 1.0 * inserted_element_num / (bucket_num * slot_num) << std::endl;
        std::cout << "bucket num = " << bucket_num << std::endl;
        std::cout << "hashtable size = " << (bucket_table.size() >> 10) << " KB" << std::endl;
        std::cout << "bits per element = " << double(bucket_table.size()) * 8 / inserted_element_num << std::endl;
        PrintSplitLine('-');
    }

};

#endif  

