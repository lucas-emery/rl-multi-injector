cmake_minimum_required(VERSION 3.17)
project(RLMultiInjector)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 17)

add_definitions(-DUNICODE -D_UNICODE)

add_executable(RLMultiInjector src/main.cpp src/DllInjector.cpp src/DllInjector.h)