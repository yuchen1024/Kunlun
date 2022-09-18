#include "stdint.h"
#include "string.h"
#include "stdlib.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifndef X25519_OPENSSL_CURVE25519_H
#define X25519_OPENSSL_CURVE25519_H

void x25519_scalar_mulx(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
#endif //X25519_OPENSSL_CURVE25519_H