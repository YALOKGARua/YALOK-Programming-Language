cmake_minimum_required(VERSION 3.20)
project(yalok VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -flto -ffast-math")

find_package(Threads REQUIRED)

include_directories(include)

set(YALOK_SOURCES
    src/token.cpp
    src/value.cpp
    src/lexer.cpp
    src/parser.cpp
    src/interpreter.cpp
    src/memory.cpp
    src/compiler.cpp
)

set(YALOK_HEADERS
    include/yalok/token.hpp
    include/yalok/value.hpp
    include/yalok/ast.hpp
    include/yalok/lexer.hpp
    include/yalok/parser.hpp
    include/yalok/interpreter.hpp
    include/yalok/memory.hpp
    include/yalok/compiler.hpp
)

add_library(yalok_lib STATIC ${YALOK_SOURCES} ${YALOK_HEADERS})
target_link_libraries(yalok_lib Threads::Threads)

add_executable(yalok src/main.cpp)
target_link_libraries(yalok yalok_lib)

install(TARGETS yalok DESTINATION bin)
install(DIRECTORY include/yalok DESTINATION include)
install(FILES README.md DESTINATION share/doc/yalok)

enable_testing()

find_package(GTest QUIET)
if(GTest_FOUND)
    add_subdirectory(tests)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
    if(ENABLE_COVERAGE)
        target_compile_options(yalok_lib PRIVATE --coverage)
        target_link_options(yalok_lib PRIVATE --coverage)
    endif()
endif()

add_custom_target(examples
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/yalok ${CMAKE_CURRENT_SOURCE_DIR}/examples/hello.yal
    DEPENDS yalok
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(benchmark
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/yalok --benchmark ${CMAKE_CURRENT_SOURCE_DIR}/examples/algorithms.yal
    DEPENDS yalok
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(format
    COMMAND find ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(lint
    COMMAND find ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include -name "*.cpp" -o -name "*.hpp" | xargs clang-tidy
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
) 