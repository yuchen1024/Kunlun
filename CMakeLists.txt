# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(Kunlun)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wno-deprecated-declarations -pthread -O3")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

include_directories("/usr/local/include")

link_directories("/usr/local/lib")
  
add_executable(test_twisted_elgamal test/test_twisted_elgamal.cpp)

target_link_libraries(test_twisted_elgamal ${OPENSSL_LIBRARIES} -lglog)

