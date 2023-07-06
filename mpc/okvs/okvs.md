# OKVS
These files implement the **oblivious key-value store** as described in the paper [Blazing Fast PSI from Improved OKVS and Subfield VOLE](https://eprint.iacr.org/2022/320). They reference the open-source implementation available at https://github.com/Visa-Research/volepsi. There is no need to compile and install third-party libraries. The implementation has been tested on Linux (Ubuntu).

## Code Structure

`OKVS` defined in Paxos.hpp is a class of the single-thread non-cluster OKVS.

`Baxos` defined in Baxos.hpp is a class of the multi-thread clustered OKVS.

**`OKVS` is a component of `Baxos`, and `Baxos` is generally used instead of `OKVS`.**

utils.h contains two parts. The first part is the operation on the gf128 domain, and the second part is unsigned integer division, refer to https://github.com/ridiculousfish/libdivide.

## Paxos

### Construction

```c++
template <typename idx_type, DenseType dense_type, typename value_type>
class OKVS{...};
```

- `idx_type`：the type for the index of key-value pair. For example, the OKVS for 200 key-value pairs needs `idx_type` to be `uint8_t`，because $200 \in [0,2^8]$
- `dense_type` : the type of the dense columns of the matrix     binary or gf128
- `value_type `: the data type of value pairs

```c++
OKVS(const idx_type item_num, const uint8_t sparse_weight, const uint8_t statistical_security_parameter, const PRG::Seed *input_seed);
```

- `const idx_type item_num`: the number of key-value pairs encoded in the OKVS
- `const uint8_t sparse_weight`: the weight of the row vector corresponding to the key during encoding
- `const uint8_t statistical_security_parameter`: statistical security parameter
- `const PRG::Seed *input_seed`：the seed for randomness during the generation of the matrix corresponding to the key set

### set_keys

This function adapter receives the starting address of the key set, and configures its corresponding matrix and other information.

```c++
void set_keys(const block *keys);
```

`const block *keys` : the address of the first element of the key set

### encode

This function adapter receives the value set and the randomization seed to calculate the structure of OKVS.

```c++
void encode(const value_type *values,const value_type *output, PRG::Seed *prng);
```

- `const value_type *values` : the address of the first element of the value set
- `const value_type *output` : the address of the first element of the data structure, which is also the target address of the encoding
- `PRG::Seed *prng `：the seed that provides randomness during the randomization process in encoding

```c++
std::vector<block> encode(const std::vector<value_type> &values, PRG::Seed *prng);
```

- `const std::vector<value_type> &values` : the vector of the value set
- `PRG::Seed *prng `：the seed that provides randomness during the randomization process in encoding
- the return value of the function is the data structure

### decode

This function adapter receives the key set and the data structure to calculate possible corresponding values.

```c++
inline void decode(const block *keys, const idx_type key_num, const value_type *output, value_type *values, block *with_dense);
```

- `const block *keys ` : the address of the first element of the key set
- `const idx_type key_num ` : the number of keys to be decoded
- `const value_type *output` : the address of the first element of the data structure, which is also the target address of the encoding
- `value_type *values ` : the address of the first element of the decoding result.
- `block* with_dense` : the address of the dense part of matrix which is optional

```c++
inline std::vector<value_type> decode(const std::vector<block> &keys, const std::vector<value_type> &output, block *with_dense);
```

- `const std::vector<block> &keys` : the vector of the key set
- `const std::vector<value_type> &output`：the vector of the data structure
- `block *with_dense` : the address of the dense part of matrix which is optional

### Sample Code

```c++
uint32_t item_num = 1ull << 20;
PRG::Seed seed = PRG::SetSeed();
std::vector<block> key_set = PRG::GenRandomBlocks(seed, item_num);
std::vector<block> value_set = PRG::GenRandomBlocks(seed, item_num);

OKVS<uint32_t, gf_128> single_thread_okvs(item_num, 3);
single_thread_okvs.set_keys(key_set.data());
std::vector<block> encode_result = single_thread_okvs.encode(value_set);
std::vector<block> decode_result = single_thread_okvs.decode(key_set, encode_result);
```

## Baxos

### Construction

```c++
template <DenseType dense_type = binary>
class Baxos{...};
```

- `dense_type` : the type of the dense columns of the matrix     binary or gf128

```c++
Baxos(const uint64_t item_num, const uint64_t bin_size, const uint8_t sparse_weight, const uint8_t statistical_security_parameter, const PRG::Seed *input_seed) ;
```

- `const idx_type item_num` : the number of key-value pairs encoded in the data structure
- `const uint64_t bin_size ` : clustering parameter
- `const uint8_t sparse_weight`:the weight of the row vector corresponding to the key during encoding
- `const uint8_t statistical_security_parameter`:statistical security parameter
- `const PRG::Seed *input_seed`：the seed for randomness during the generation of the matrix corresponding to the key set

### solve

This function adapter receives the key set, the value set and the randomization seed to calculate the data structure.

```c++
void solve(const std::vector<block> &keys, const std::vector<block> &values, std::vector<block> &output, PRG::Seed *prng, uint8_t thread_num);
```

- `const std::vector<block> &keys` : the vector of the key set
- `const std::vector<block> &values` : the vector of the value set
- `std::vector<block> &output` : the data structure **to be calculated**
- `PRG::Seed *prng `：the seed that provides randomness during the randomization process in encoding
- `uint8_t thread_num` : the number o threads

### decode

This function adapter receives the key set and the data structure to calculate possible corresponding values.

```c++
void decode(const std::vector<block> &keys, std::vector<block> &values, const std::vector<block> &output, uint8_t thread_num);
```

- `const std::vector<block> &keys` : the vector of the key set
- `const std::vector<block> &values` : the possible value set **to be calculated**
- `std::vector<block> &output` : the data structure
- `uint8_t thread_num` : the number o threads

### Samlple Code

```c++
uint64_t item_num = 1ull << 20;
uint64_t bin_size = 1 << 15;
PRG::Seed seed = PRG::SetSeed(fixed_seed, 0);

std::vector<block> value_set = PRG::GenRandomBlocks(seed, item_num);
std::vector<block> key_set = PRG::GenRandomBlocks(seed, item_num);
std::vector<block> decode_result(item_num);

Baxos<gf_128> baxos(item_num, bin_size, 3);
std::vector<block> encode_result(baxos.bin_num * baxos.total_size);

uint8_t thread_num = 4;
baxos.solve(key_set, value_set, encode_result, &seed, thread_num);
baxos.decode(key_set, decode_result, encode_result, thread_num);
```

## Compile and run

```c++
$ mkdir build && cd build
$ cmake ..
$ make
$ ./test_okvs 
```
