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
)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 


# netio
ADD_EXECUTABLE(test_netio test/test_netio.cpp)
TARGET_LINK_LIBRARIES(test_netio ${OPENSSL_LIBRARIES} -lomp)

# filter
ADD_EXECUTABLE(test_bloom_filter test/test_bloom_filter.cpp)
TARGET_LINK_LIBRARIES(test_bloom_filter ${OPENSSL_LIBRARIES} -lomp)

# ot
ADD_EXECUTABLE(test_naor_pinkas_ot test/test_naor_pinkas_ot.cpp)
TARGET_LINK_LIBRARIES(test_naor_pinkas_ot ${OPENSSL_LIBRARIES} -lomp)

ADD_EXECUTABLE(test_iknp_ote test/test_iknp_ote.cpp)
target_link_libraries(test_iknp_ote ${OPENSSL_LIBRARIES} -lomp)

# pso
ADD_EXECUTABLE(test_psu test/test_psu.cpp)
TARGET_LINK_LIBRARIES(test_psu ${OPENSSL_LIBRARIES} -lomp)

ADD_EXECUTABLE(test_psi test/test_psi.cpp)
TARGET_LINK_LIBRARIES(test_psi ${OPENSSL_LIBRARIES} -lomp)

# misc
ADD_EXECUTABLE(test_misc test/test_misc.cpp)
TARGET_LINK_LIBRARIES(test_misc ${OPENSSL_LIBRARIES} -lomp)
  
# pke  
ADD_EXECUTABLE(test_twisted_elgamal test/test_twisted_elgamal.cpp)
TARGET_LINK_LIBRARIES(test_twisted_elgamal ${OPENSSL_LIBRARIES} -lomp)

ADD_EXECUTABLE(test_calculate_dlog test/test_calculate_dlog.cpp)
TARGET_LINK_LIBRARIES(test_calculate_dlog ${OPENSSL_LIBRARIES} -lomp)

# nike
ADD_EXECUTABLE(test_nizk_plaintext_equality test/test_nizk_plaintext_equality.cpp)
TARGET_LINK_LIBRARIES(test_nizk_plaintext_equality ${OPENSSL_LIBRARIES} -lomp)

ADD_EXECUTABLE(test_nizk_plaintext_knowledge test/test_nizk_plaintext_knowledge.cpp)
TARGET_LINK_LIBRARIES(test_nizk_plaintext_knowledge ${OPENSSL_LIBRARIES} -lomp)

ADD_EXECUTABLE(test_nizk_dlog_equality test/test_nizk_dlog_equality.cpp)
TARGET_LINK_LIBRARIES(test_nizk_dlog_equality ${OPENSSL_LIBRARIES} -lomp)

# bulletproof
ADD_EXECUTABLE(test_innerproduct_proof test/test_innerproduct_proof.cpp)
TARGET_LINK_LIBRARIES(test_innerproduct_proof ${OPENSSL_LIBRARIES} -lomp)

ADD_EXECUTABLE(test_bullet_proof test/test_bullet_proof.cpp)
TARGET_LINK_LIBRARIES(test_bullet_proof ${OPENSSL_LIBRARIES} -lomp)

# gadget
ADD_EXECUTABLE(test_range_proof test/test_range_proof.cpp)
TARGET_LINK_LIBRARIES(test_range_proof ${OPENSSL_LIBRARIES} -lomp)

# cryptocurrency
ADD_EXECUTABLE(test_adct test/test_adct.cpp)
TARGET_LINK_LIBRARIES(test_adct ${OPENSSL_LIBRARIES} -lomp)

