# Specify the minimum version for CMake
CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

# Project's name 
PROJECT(Kunlun)

FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(OpenMP REQUIRED)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fpic -flto -Wno-deprecated-declarations -Wno-unused-result -Xpreprocessor -O3 -DNDEBUG -Wall")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mpclmul -msse2 -std=c++14  -mavx -mavx2 -g -DNDEBUG -fpic -flto -Wno-deprecated-declarations -Wno-unused-result -Xpreprocessor -march=native -Wall -Wfatal-errors")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14  -g ")

INCLUDE_DIRECTORIES(
    ${OPENSSL_INCLUDE_DIR}
    "/usr/local/include"
)

LINK_DIRECTORIES(
    /usr/local/lib
)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 



ADD_EXECUTABLE(test_okvs ./test_okvs.cpp)

if(OpenMP_CXX_FOUND)
    target_compile_options(test_okvs PUBLIC ${OpenMP_CXX_FLAGS})
endif()
target_compile_options(test_okvs PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++14> -lpthread)

TARGET_LINK_LIBRARIES(test_okvs ${OPENSSL_LIBRARIES} OpenMP::OpenMP_CXX)

