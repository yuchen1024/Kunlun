void test_endian()
{
    std::cout << sizeof(block) << std::endl; 
    std::vector<uint8_t> A(16); 
    A[0] = 0xFF;
    A[1] = 0x0F; 
    A[2] = 0xF0; 
    A[3] = 0xDD; 
    A[4] = 0xFF;
    A[5] = 0x01; 
    A[6] = 0x10; 
    A[7] = 0x25; 
    A[8] = 0x56;
    A[9] = 0x34; 
    A[10] = 0x67; 
    A[11] = 0x98; 
    A[12] = 0x22;
    A[13] = 0x41; 
    A[14] = 0x38; 
    A[15] = 0x66; 

    block B; 
    memcpy(&B, A.data(), 16); 

    //PrintBlock(B); 
}

void test_matrix_transpose()
{
    size_t ROW_NUM = 1024*1024; 
    size_t COLUMN_NUM = 128;

    PRG::Seed seed; 
    PRG::SetSeed(seed, nullptr, 0); 
    std::vector<uint8_t> T1 = PRG::GenRandomBitMatrix(seed, ROW_NUM, COLUMN_NUM); 
    //PrintBitMatrix(T1.data(), ROW_NUM, COLUMN_NUM);  

    std::vector<uint8_t> T2(ROW_NUM/8 * COLUMN_NUM); 
    // SSE_BitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());
    BitMatrixTranspose(T1.data(), ROW_NUM, COLUMN_NUM, T2.data());
    //PrintBitMatrix(T2.data(), COLUMN_NUM, ROW_NUM); 

    std::vector<uint8_t> T3(ROW_NUM/8 * COLUMN_NUM); 
    // SSE_BitMatrixTranspose(T.data(), ROW_NUM, COLUMN_NUM, T_transpose.data());
    BitMatrixTranspose(T2.data(), COLUMN_NUM, ROW_NUM, T3.data());
    //PrintBitMatrix(T3.data(), ROW_NUM, COLUMN_NUM);

    CompareMatrix(T1.data(), T3.data(), ROW_NUM, COLUMN_NUM); 
}


void CompareMatrix(uint8_t *M1, uint8_t *M2, size_t ROW_NUM, size_t COLUMN_NUM)
{
    bool EQUAL = true; 
    for(auto i = 0; i < ROW_NUM/8 * COLUMN_NUM; i++){
        if(M1[i]!=M2[i]){
            std::cout << i << std::endl;
            EQUAL = false; 
            break;
        }
    }
    if (EQUAL) std::cout << "the two matrix are equal" << std::endl;
    else std::cout << "the two matrix are not equal" << std::endl;
}
