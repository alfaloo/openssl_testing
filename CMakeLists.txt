cmake_minimum_required(VERSION 3.12)
project(OPENSSL_TESTING)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS "-std=c++20 -O2 -DNDEBUG")

add_executable(Client ${PROJECT_SOURCE_DIR}/Client.cpp)
target_include_directories(Client PRIVATE ${PROJECT_SOURCE_DIR} /usr/local/include)
target_link_libraries(Client PRIVATE /usr/local/lib64/libssl.so /usr/local/lib64/libcrypto.so)
set_target_properties(Client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build)

add_executable(Server ${PROJECT_SOURCE_DIR}/Server.cpp)
target_include_directories(Server PRIVATE ${PROJECT_SOURCE_DIR} /usr/local/include)
target_link_libraries(Server PRIVATE /usr/local/lib64/libssl.so /usr/local/lib64/libcrypto.so)
set_target_properties(Server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build)