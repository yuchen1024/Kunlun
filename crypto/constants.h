#ifndef KUNLUN_CONSTANT_H_
#define KUNLUN_CONSTANT_H_

const static size_t AES_BATCH_SIZE = 8;
const static size_t HASH_BUFFER_SIZE = 1024*8;
const static size_t NETWORK_BUFFER_SIZE = 1024*1024;
const static size_t FILE_BUFFER_SIZE = 1024*16;
const static size_t CHECK_BUFFER_SIZE = 1024*8;

const static size_t HASH_OUTPUT_LEN = 32;  // hash output = 256-bit string


const char fix_key[] = "\x61\x7e\x8d\xa2\xa0\x51\x1e\x96\x5e\x41\xc2\x9b\x15\x3f\xc7\x7a";

const static uint64_t fixed_salt = 0xAAAAAAAA; // used for murmurhash

#endif
