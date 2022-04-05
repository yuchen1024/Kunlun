/*
** Modified from the following project
** 1. https://github.com/emp-toolkit/
*/

#ifndef KUNLUN_PRP_HPP_
#define KUNLUN_PRP_HPP_

#include "aes.hpp"
#include "constants.h"


/*
 * When the key is public, we usually need to model AES with this public key as a random permutation.
 * [REF] "Efficient Garbling from a Fixed-Key Blockcipher" https://eprint.iacr.org/2013/426.pdf
*/

namespace PRP{

void AES::Key GenKey(const block& salt)
{
    return AES::GenEncKey(salt);
}

// key plays the role of enc key
block Evaluate(AES::Key &key, const block &data) {
    return AES::ECBEnc(enc_key, data);
}

block Inverse(AES::Key &key, const block &data) {
    AES::dec_key = AES::DeriveDecKeyFromEncKey(key);
    return AES::ECBDec(dec_key, data);
}

}
#endif