#ifndef KUNLUN_UTILITY_BLOCK_HPP__
#define KUNLUN_UTILITY_BLOCK_HPP__

#include <immintrin.h>
#include <assert.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>


typedef __m128i block;

inline bool GetLSB(const block &a) {
   return (a[0] & 1) == 1;
}


// generate a block from two uint64_t values
__attribute__((target("sse2")))
inline block MakeBlock(uint64_t &high, uint64_t &low) {
	 return _mm_set_epi64x(high, low);
}


/* Linear orthomorphism function
 * [REF] Implementation of "Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers"
 * https://eprint.iacr.org/2019/074.pdf
 */

__attribute__((target("sse2")))
inline block Sigma(block a) {
	 return _mm_shuffle_epi32(a, 78) ^ (a & MakeBlock(0xFFFFFFFFFFFFFFFF, 0x00));
}

const block zero_block = MakeBlock(0, 0);
const block all_one_block = MakeBlock(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
const block select_mask[2] = {zero_block, all_one_block};

inline block SetBit(const block &a, size_t i) 
{
    if(i < 64) return MakeBlock(0L, 1ULL<<i) | a;
	  else return MakeBlock(1ULL<<(i-64), 0L) | a;
}

inline std::ostream& operator<<(std::ostream &out, const block &a) 
{
    out << std::hex;
	  uint64_t* data = (uint64_t*)&a;

	  out << std::setw(16) << std::setfill('0') << data[1]
		<< std::setw(16) << std::setfill('0') << data[0];

	  out << std::dec << std::setw(0);
	  return out;
}


inline void XOR_Blocks(block* result, const block* a, const block* b, size_t BLOCK_LEN) 
{
	  for (auto i = 0; i < BLOCK_LEN; i++){
      result[i] = a[i] ^ b[i];
    }
}

inline void XOR_Blocks(block* result, const block* a, const block* b, size_t BLOCK_LEN) 
{
	  for (auto i = 0; i < BLOCK_LEN; i++){
        result[i] = a[i] ^ b;
    }
}


__attribute__((target("sse4")))
inline bool CompareBlock(block* a, block* b, size_t BLOCK_LEN) 
{
	  for (auto i = 0; i < BLOCK_LEN; i++) 
    {
		   __m128i vcmp = _mm_xor_si128(*(a++), *(b++));
		   if(!_mm_testz_si128(vcmp, vcmp))
			 return false;
	  }
	  return true;
}

//Modified from
//https://mischasan.wordpress.com/2011/10/03/the-full-sse2-bit-matrix-transpose-routine/
// with inner most loops changed to _mm_set_epi8 and _mm_set_epi16
#define INPUT(x, y) input[(x)*ncols / 8 + (y) / 8]
#define OUTPUT(x, y) output[(y)*nrows / 8 + (x) / 8]

__attribute__((target("sse2")))

inline void SSE_BitMatrix_Transpose(uint8_t *output, uint8_t const *input, uint64_t ROW_NUM, uint64_t COLUMN_NUM) {
    uint64_t rr, cc;
    int i, h;
    union{
      __m128i x;
      uint8_t b[16];
    } tmp;
    __m128i vec;
    assert(ROW_NUM%8 == 0 && COLUMN_NUM%8 == 0);

    // Do the main body in 16x8 blocks:
    for (rr = 0; rr <= ROW_NUM - 16; rr += 16) {
        for (cc = 0; cc < COLUMN_NUM; cc += 8) {
            vec = _mm_set_epi8(INPUT(rr + 15, cc), INPUT(rr + 14, cc), INPUT(rr + 13, cc),
                               INPUT(rr + 12, cc), INPUT(rr + 11, cc), INPUT(rr + 10, cc),
                               INPUT(rr + 9, cc),  INPUT(rr + 8, cc),  INPUT(rr + 7, cc),
                               INPUT(rr + 6, cc),  INPUT(rr + 5, cc),  INPUT(rr + 4, cc),
                               INPUT(rr + 3, cc),  INPUT(rr + 2, cc),  INPUT(rr + 1, cc),
                               INPUT(rr + 0, cc));
            for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1))
              *(uint16_t *)&OUTPUT(rr, cc + i) = _mm_movemask_epi8(vec);
        }
    }
    if (rr == ROW_NUM)
    return;

    // The remainder is a block of 8x(16n+8) bits (n may be 0).
    //  Do a PAIR of 8x8 blocks in each step:
    if ((COLUMN_NUM%8 == 0 && COLUMN_NUM%16 != 0) || (ROW_NUM%8 == 0 && ROW_NUM%16 != 0)) {
        // The fancy optimizations in the else-branch don't work if the above if-condition
        // holds, so we use the simpler non-simd variant for that case.
        for (cc = 0; cc <= COLUMN_NUM - 16; cc += 16) {
            for (i = 0; i < 8; ++i) {
                tmp.b[i] = h = *(uint16_t const *)&INPUT(rr + i, cc);
                tmp.b[i + 8] = h >> 8;
            }
            for (i = 8; --i >= 0; tmp.x = _mm_slli_epi64(tmp.x, 1)) {
                OUTPUT(rr, cc + i) = h = _mm_movemask_epi8(tmp.x);
                OUTPUT(rr, cc + i + 8) = h >> 8;
            }
        }
    } 
    else {
        for (cc = 0; cc <= COLUMN_NUM - 16; cc += 16) {
            vec = _mm_set_epi16(*(uint16_t const *)&INPUT(rr + 7, cc),
                                *(uint16_t const *)&INP(rr + 6, cc),
                                *(uint16_t const *)&INP(rr + 5, cc),
                                *(uint16_t const *)&INP(rr + 4, cc),
                                *(uint16_t const *)&INP(rr + 3, cc),
                                *(uint16_t const *)&INP(rr + 2, cc),
                                *(uint16_t const *)&INP(rr + 1, cc),
                                *(uint16_t const *)&INP(rr + 0, cc));
            for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1)) {
                OUTPUT(rr, cc + i) = h = _mm_movemask_epi8(vec);
                OUTPUT(rr, cc + i + 8) = h >> 8;
            }
        }
    }
    if (cc == COLUMN_NUM) return;

    //  Do the remaining 8x8 block:
    for (i = 0; i < 8; ++i)
        tmp.b[i] = INPUT(rr + i, cc);
    for (i = 8; --i >= 0; tmp.x = _mm_slli_epi64(tmp.x, 1))
        OUTPUT(rr, cc + i) = _mm_movemask_epi8(tmp.x);
}
#endif
