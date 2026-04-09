cmake_minimum_required(VERSION 3.16)
project(yalok LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(yalok
    src/main.cpp
    src/lexer.cpp
    src/parser.cpp
    src/interpreter.cpp
)

target_include_directories(yalok PRIVATE include)

if(MSVC)
    target_compile_options(yalok PRIVATE /W4 /permissive-)
else()
    target_compile_options(yalok PRIVATE -Wall -Wextra -O2)
endif()
