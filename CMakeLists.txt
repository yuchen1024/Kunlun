# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(Kunlun)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wno-deprecated-declarations -Xpreprocessor -fopenmp -pthread -O3")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

include_directories("/usr/local/include")

link_directories("/usr/local/lib")
  
add_executable(test_twisted_elgamal test/test_twisted_elgamal.cpp)
target_link_libraries(test_twisted_elgamal ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(dummy_test test/dummy_test.cpp)
target_link_libraries(dummy_test ${OPENSSL_LIBRARIES} -lglog)

add_executable(test_nizk_plaintext_equality test/test_nizk_plaintext_equality.cpp)
target_link_libraries(test_nizk_plaintext_equality ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(test_nizk_plaintext_knowledge test/test_nizk_plaintext_knowledge.cpp)
target_link_libraries(test_nizk_plaintext_knowledge ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(test_nizk_dlog_equality test/test_nizk_dlog_equality.cpp)
target_link_libraries(test_nizk_dlog_equality ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(test_innerproduct_proof test/test_innerproduct_proof.cpp)
target_link_libraries(test_innerproduct_proof ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(test_bullet_proof test/test_bullet_proof.cpp)
target_link_libraries(test_bullet_proof ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(test_range_proof test/test_range_proof.cpp)
target_link_libraries(test_range_proof ${OPENSSL_LIBRARIES} -lglog -lomp)

add_executable(test_adct test/test_adct.cpp)
target_link_libraries(test_adct ${OPENSSL_LIBRARIES} -lglog -lomp)

