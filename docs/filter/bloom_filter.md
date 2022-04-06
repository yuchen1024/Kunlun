# Bloom Filter
`BloomFilter` is a class of the data structure, bloom filter. It is used in [`PSO`](../mpc/pso/pso_from_mqrpmt.md) to do membership test. Other than the basic interface `Insert` for inserting elements to a bloom filter and `Contain` for querying, `BloomFilter` also provides serialize/deserialize interfaces.

## Construction
```
BloomFilter(size_t projected_element_num, size_t statistical_security_parameter);
```
* `size_t projected_element_num`: the number of elements inserted into the bloom filter.
* `size_t statistical_security_parameter`: used to specify the false positive probability of bloom filter, which equals `1/(1 << {statistical_security_parameter/2})`.

### Clear
```
inline void Clear();
```
Clear the contents of bloom filter, and sets the `projected_element_num` back to 0.

## Use
### Serialization
```
size_t ObjectSize();
```
Get the number of bytes a `BloomFilter` object takes.

```
inline bool WriteObject(std::string file_name);

inline bool WriteObject(char* buffer);
```
Write a `BloomFilter` object to file or the location `buffer` points to, `WriteObject` returns true if it succeeds. The caller need to allocate memory space of `buffer` previously, which is the value returned from `ObjectSize`.

```
inline bool ReadObject(std::string file_name);

inline bool ReadObject(char* buffer);
```
Read a `BloomFilter` object from file or the location `buffer` points to, `ReadObject` returns true if it succeeds.

### Insert
Insert a single element to the `BloomFilter`. The type of element should be any C++ POD type or `ECPoint`.
```
template <typename ElementType> // Note: T must be a C++ POD type.
inline void Insert(const ElementType& element);

inline void Insert(const ECPoint &A);
```

Insert multiple elements from `begin` to `end`.
```
template <typename InputIterator>
inline void Insert(const InputIterator begin, const InputIterator end);
``` 
* `InputIterator begin` and `InputIterator end`: the begin and end iterators for your data. This will behave like any STL iterator-based algorithm.

Insert all elements in a STL `Container`.
```
template <class T, class Allocator, template <class,class> class Container>
inline void Insert(Container<T, Allocator>& container);

inline void Insert(const std::vector<ECPoint> &vec_A);
```

### Query
Query if an element is in the `BloomFilter`. The type of element should be any C++ POD type or `ECPoint`. Note that if the element type is `std::string`, it will call the specialized template function of `Contain`.
```
template <typename ElementType>
inline bool Contain(const ElementType& element) const;

inline bool Contain(const std::string& str) const;

inline bool Contain(const ECPoint& A) const;
```

### Print Information
```
void PrintInfo();
```
Get the state of the `BloomFilter`, such as the number of inserted elements, hashtable size and the average number of bits per element.

## Sample Code
An example of how to build a bloom filter with $2^{20}$ random blocks. More detailed sample code is provided in test files.
```
size_t NUM = 1 << 20;
BloomFilter filter(NUM, 40);

PRG::Seed seed; 
PRG::SetSeed(seed, fix_key, 0); // initialize PRG
std::vector<block> setX = PRG::GenRandomBlocks(seed, NUM);

for (auto i = 0; i < NUM; i++)
{
    filter.Insert(setX[i]);
}

for (auto i = 0; i < NUM; i++)
{
    if (filter.Contain(setX[i]) == false) {
         std::cout << " wrong " << std::endl;
    }
}
```
