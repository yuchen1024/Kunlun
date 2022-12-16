#include "../crypto/aes.hpp"
#include "../crypto/setup.hpp"

int main()
{  
    CRYPTO_Initialize(); 
    
    std::ios::sync_with_stdio(false);

    PrintSplitLine('-'); 
    std::cout << "AES test begins >>>>>>" << std::endl; 

    ECPoint A = ECPoint(generator);

    unsigned char buffer[POINT_BYTE_LEN];
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, nullptr);
    block data[4]; 
    data[0] = _mm_loadu_si128(((block *)(&buffer[0 ]))); 
    data[1] = _mm_loadu_si128(((block *)(&buffer[16]))); 
    data[2] = _mm_loadu_si128(((block *)(&buffer[32]))); 
    data[3] = _mm_loadu_si128(((block *)(&buffer[48])));
    PrintSplitLine('-');
    std::cout << "plaintext ==" << std::endl; 
    Block::PrintBlocks(data, 4); 
    PrintSplitLine('-');
    
    std::cout << "after encryption ==" << std::endl; 
    AES::CBCEnc(AES::fixed_enc_key, data, 4);
    Block::PrintBlocks(data, 4); 
    PrintSplitLine('-');

    std::cout << "after decryption ==" << std::endl; 
    AES::CBCDec(AES::fixed_dec_key, data, 4);
    Block::PrintBlocks(data, 4); 
    PrintSplitLine('-');

    CRYPTO_Finalize(); 
    return 0; 
}