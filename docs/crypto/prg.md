# Pseudorandom Generator
This file implements `PRG` using [`AES`](./aes.md). 


## Construction
All identifiers are defined in namespace `PRG`.

```
struct Seed{ 
    size_t counter = 0; 
    AES::Key aes_key;
};
```
* `size_t counter`: records the state of `PRG`.
* `AES::Key`: a struct at namespace [`AES`](./aes.md), which depics the AES key.

### SetSeed
Initialize the PRG seed.
```
Seed SetSeed(const void* salt = nullptr, uint64_t id = 0);
```
* `const void* salt`: the random data needed to initialize the PRG seed. It can be assigned by the caller or generated in the function by default.
* `uint64_t id`: the identidier of `PRG` in use. Default to 0 if unset.

### ReSeed
Reset the PRG seed using the random data assigned by the caller.
```
void ReSeed(Seed &seed, const block* salt, uint64_t id = 0);
```
* `Seed &seed`: the seed needs to be reseted.
* `const block* salt`: a random block assigned by the caller to set the PRG seed.
* `uint64_t id`: the identidier of `PRG` in use. Default to 0 if unset.


## Use 
### GenRandomBlocks
Generate a random block vector.
```
std::vector<block> GenRandomBlocks(Seed &seed, size_t LEN);
```
* `Seed &seed`: the PRG seed.
* `size_t LEN`: the length of the generated vector. 

### GenRandomBytes
Generate a random byte vector.
```
std::vector<uint8_t> GenRandomBytes(Seed &seed, size_t LEN);
```
* `Seed &seed`: the PRG seed.
* `size_t LEN`: the length of the generated vector.

### GenRandomBits 
Generate a random bool vector: each byte represents a bit in a sparse way.
```
std::vector<uint8_t> GenRandomBits(Seed &seed, size_t LEN);
```
* `Seed &seed`: the PRG seed.
* `size_t LEN`: the length of the generated vector.

### GenRandomBitMatrix
Generate a random bit matrix, which is stored in column vector.
```
std::vector<uint8_t> GenRandomBitMatrix(Seed &seed, size_t ROW_NUM, size_t COLUMN_NUM);
```
* `Seed &seed`: the PRG seed.
* `size_t ROW_NUM`: the number of rows in the matrix.
* `size_t COLUMN_NUM`: the number of columns in the matrix.

### CompareBits
`CompareBits` checks if two bit vectors are equal, returns true if they are equal, returns false if they are not.
```
bool CompareBits(std::vector<uint8_t>& vec_A,  std::vector<uint8_t>& vec_B);
```
* `std::vector<uint8_t>& vec_A` and `std::vector<uint8_t>& vec_B`: the bit vector needs to be compared.
