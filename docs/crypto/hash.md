# Hash
This file implements basic hash based on SM3 and AES CBC encryption, and provides interfaces with different input data type.

## Use
### Basic Hash
Adaptor for SM3: default output length is 256 bit.
```
void SM3(const unsigned char *input, size_t HASH_INPUT_LEN, unsigned char *output);
```
* `const unsigned char *input`: a pointer of `char` points to the input hashing data. 
* `size_t HASH_INPUT_LEN`: the byte length of the input hashing data.
* `unsigned char *output`: a pointer of `char` points to the output hashing data. 

Adaptor for CBC-AES hash: default output length is 128 bit.
```
void CBCAES(const unsigned char *input, size_t HASH_INPUT_LEN, unsigned char *output);
```
* `const unsigned char *input`: a pointer of `char` points to the input hashing data. 
* `size_t HASH_INPUT_LEN`: the byte length of the input hashing data.
* `unsigned char *output`: a pointer of `char` points to the output hashing data. 

### Hash String to Other
Hash a `string` to a `block`.
```
block StringToBlock(const std::string &str_input);
```

Hash a `string` to a `BigInt`. 
```
BigInt StringToBigInt(const std::string& str_input);
```

Hash a `string` to an `ECPoint`.
```
ECPoint StringToECPoint(const std::string& input);
```

### Hash ECPoint to Other
Hash an `ECPoint` to a `block`.
```
block ECPointToBlock(const ECPoint &A); 
```

Hash an `ECPoint` to a `string`.
```
std::string ECPointToString(const ECPoint &A);
```

### Hash Block to Other
Hash a vector of `block`s to a `block`.
```
block BlocksToBlock(const std::vector<block> &input_block);
```

Hash a `block` to an `ECPoint`. Note that if you enable the multi-thread programing, you should call `ThreadSafeBlockToECPoint` to ensure correctness.
```
inline ECPoint BlockToECPoint(const block &var);

inline ECPoint ThreadSafeBlockToECPoint(const block &var);
```
