# Routine Algorithms
This file implements some routine algorithms.


## Utility Functions
### FileExist
`FileExist` checks whether a file named `filename` exists, returns true if it exists, returns false if not.
```
inline bool FileExist(const std::string& filename);
```

### FormatToHexString
`FormatToHexString` formats the input `byte_str` which is an octet string to a hexadecimal string. 
```
std::string FormatToHexString(std::string byte_str);
```

### IsPowerOfTwo
`IsPowerOfTwo` checks whether there exists an integer $n$ satisfies $x = 2^n$ for $x > 0$, returns true if integer $n$ exists, returns false if not.
```
bool IsPowerOfTwo(size_t x);
```

### GenRandomIntegerVectorLessThan
`GenRandomIntegerVectorLessThan` returns a random integer vector. The vector generated in this way does not require cryptographic security. 
```
std::vector<int64_t> GenRandomIntegerVectorLessThan(size_t LEN, int64_t MAX);
```
 *  `size_t LEN`: the length of the generated integer vector.
 * `int64_t MAX`: the range of each value in the generated vector is limited to [0,...,MAX].
