# AES
`AES` implements AES using Streaming SIMD Extensions2 (SSE2) instructions. The block showed in this file is a `__m128i` data type in SSE2. And it's defined in [block.hpp](../../crypto/block.hpp).


## Construction
All identifiers are defined in namespace `AES`.
```
struct Key{ 
    block roundkey[11]; 
    size_t ROUND_NUM; 
};
```
* `block roundkey[11]`: the keys used in each round.
* `size_t ROUND_NUM`: the total times of encryption round or decryption round. `ROUND_NUM` equals 10 since the length of round key is 128 bits.

### Encryption Key Generation
Generate the encryption key of AES with a random input.
```
inline Key GenEncKey(const block &salt);
```
* `const block &salt`: a random block assigned by the caller to generate the encryption key.

### Decryption Key Generation
There are two ways of generating decryption key.
```
inline Key GenDecKey(const block &salt);
```
* `const block &salt`: a random block assigned by the caller to generate the decryption key. To ensure correct decryption, it should be the same `salt` generating the encryption key.

```
inline Key DeriveDecKeyFromEncKey(const Key &enc_key);
```
* `const Key &enc_key`: the encryption key from which decryption key derived.


## Use
### ECB Mode
Encrypt `BLOCK_LEN` blocks source from the object pointed to by `data` using ECB mode.
```
inline void ECBEnc(const Key &key, block* data, size_t BLOCK_LEN);
```
* `const Key &key`: the AES encryption key.
* `block* data`: pointer to the memory location to encrypt from. Instead of allocating a new memory location, the generated ciphertext will cover the location points by `data`.
* `size_t BLOCK_LEN`: the number of blocks to encrypt.

Decrypt `BLOCK_LEN` blocks source from the object pointed to by `data`.
```
inline void ECBDec(const Key &key, block* data, size_t BLOCK_LEN);
```
* `const Key &key`: the AES decryption key.
* `block* data`: pointer to the memory location to decrypt from. Instead of allocating a new memory location, the generated plaintext will cover the location points by `data`.
* `size_t BLOCK_LEN`: the number of blocks to decrypt.

### CBC Mode
Encrypt `BLOCK_LEN` blocks source from the object pointed to by `data` using CBC mode.
```
inline void CBCEnc(const Key &key, block* data, size_t BLOCK_LEN);
```
* `const Key &key`: the AES encryption key.
* `block* data`: pointer to the memory location to encrypt from. Instead of allocating a new memory location, the generated ciphertext will cover the location points by `data`.
* `size_t BLOCK_LEN`: the number of blocks to encrypt.

Decrypt `BLOCK_LEN` blocks source from the object pointed to by `data`.
```
inline void CBCDec(const Key &key, block* data, size_t BLOCK_LEN);
```
* `const Key &key`: the AES decryption key.
* `block* data`: pointer to the memory location to decrypt from. Instead of allocating a new memory location, the generated plaintext will cover the location points by `data`.
* `size_t BLOCK_LEN`: the number of blocks to decrypt.


## Sample Code
An example of how to encrypt an `ECPoint` with AES CBC mode. More detailed sample code is provided in test files.
```
ECPoint A = ECPoint(generator);

unsigned char buffer[POINT_BYTE_LEN];
EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
block data[4]; 
data[0] = _mm_loadu_si128(((block *)(&buffer[0 ]))); 
data[1] = _mm_loadu_si128(((block *)(&buffer[16]))); 
data[2] = _mm_loadu_si128(((block *)(&buffer[32]))); 
data[3] = _mm_loadu_si128(((block *)(&buffer[48])));

std::cout << "plaintext ==" << std::endl; 
PrintBlocks(data, 4); 
    
std::cout << "after encryption ==" << std::endl; 
AES::CBCEnc(fix_aes_enc_key, data, 4);
PrintBlocks(data, 4); 

std::cout << "after decryption ==" << std::endl; 
AES::CBCDec(fix_aes_dec_key, data, 4);
PrintBlocks(data, 4); 
```
