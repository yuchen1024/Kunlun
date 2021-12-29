# Specify the minimum version for CMake
CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

# Project's name 
PROJECT(Kunlun)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fno-pic -Wno-deprecated-declarations -Xpreprocessor -fopenmp -pthread -O3")

FIND_PACKAGE(OpenSSL REQUIRED)

INCLUDE_DIRECTORIES(
    ${OPENSSL_INCLUDE_DIR}
    "/usr/local/include"
)

LINK_DIRECTORIES(
    /usr/local/lib
    lib
)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 


# netio
ADD_EXECUTABLE(test_netio test/test_netio.cpp)
TARGET_LINK_LIBRARIES(test_netio ${OPENSSL_LIBRARIES} -lomp -lblake3)

# filter
ADD_EXECUTABLE(test_bloom_filter test/test_bloom_filter.cpp)
TARGET_LINK_LIBRARIES(test_bloom_filter ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_cuckoo_filter test/test_cuckoo_filter.cpp)
TARGET_LINK_LIBRARIES(test_cuckoo_filter ${OPENSSL_LIBRARIES} -lomp -lblake3)

# ot
ADD_EXECUTABLE(test_naor_pinkas_ot test/test_naor_pinkas_ot.cpp)
TARGET_LINK_LIBRARIES(test_naor_pinkas_ot ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_iknp_ote test/test_iknp_ote.cpp)
TARGET_LINK_LIBRARIES(test_iknp_ote ${OPENSSL_LIBRARIES} -lomp -lblake3)

# pso
ADD_EXECUTABLE(test_psu test/test_psu.cpp)
TARGET_LINK_LIBRARIES(test_psu ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_psi test/test_psi.cpp)
TARGET_LINK_LIBRARIES(test_psi ${OPENSSL_LIBRARIES} -lomp -lblake3)

# misc
ADD_EXECUTABLE(test_misc test/test_misc.cpp)
TARGET_LINK_LIBRARIES(test_misc ${OPENSSL_LIBRARIES} -lomp -lblake3)
  
# pke  
ADD_EXECUTABLE(test_twisted_elgamal test/test_twisted_elgamal.cpp)
TARGET_LINK_LIBRARIES(test_twisted_elgamal ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_calculate_dlog test/test_calculate_dlog.cpp)
TARGET_LINK_LIBRARIES(test_calculate_dlog ${OPENSSL_LIBRARIES} -lomp -lblake3)

# accountable ring signature
ADD_EXECUTABLE(test_accountable_ring_sig test/test_accountable_ring_sig.cpp)
TARGET_LINK_LIBRARIES(test_accountable_ring_sig ${OPENSSL_LIBRARIES} -lomp -lblake3)

# nike
ADD_EXECUTABLE(test_nizk_enc_relation test/test_nizk_enc_relation.cpp)
TARGET_LINK_LIBRARIES(test_nizk_enc_relation ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_nizk_dlog_knowledge test/test_nizk_dlog_knowledge.cpp)
TARGET_LINK_LIBRARIES(test_nizk_dlog_knowledge ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_nizk_plaintext_equality test/test_nizk_plaintext_equality.cpp)
TARGET_LINK_LIBRARIES(test_nizk_plaintext_equality ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_nizk_plaintext_knowledge test/test_nizk_plaintext_knowledge.cpp)
TARGET_LINK_LIBRARIES(test_nizk_plaintext_knowledge ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_nizk_dlog_equality test/test_nizk_dlog_equality.cpp)
TARGET_LINK_LIBRARIES(test_nizk_dlog_equality ${OPENSSL_LIBRARIES} -lomp -lblake3)

# bulletproof
ADD_EXECUTABLE(test_innerproduct_proof test/test_innerproduct_proof.cpp)
TARGET_LINK_LIBRARIES(test_innerproduct_proof ${OPENSSL_LIBRARIES} -lomp -lblake3)

ADD_EXECUTABLE(test_bullet_proof test/test_bullet_proof.cpp)
TARGET_LINK_LIBRARIES(test_bullet_proof ${OPENSSL_LIBRARIES} -lomp -lblake3)

# gadget
ADD_EXECUTABLE(test_range_proof test/test_range_proof.cpp)
TARGET_LINK_LIBRARIES(test_range_proof ${OPENSSL_LIBRARIES} -lomp -lblake3)

# cryptocurrency
ADD_EXECUTABLE(test_adct test/test_adct.cpp)
TARGET_LINK_LIBRARIES(test_adct ${OPENSSL_LIBRARIES} -lomp -lblake3)