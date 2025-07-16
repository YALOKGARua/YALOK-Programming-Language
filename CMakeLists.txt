cmake_minimum_required(VERSION 3.20)
project(YALOK VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(ENABLE_SIMD "Enable SIMD optimizations" ON)
option(ENABLE_PARALLEL "Enable parallel execution" ON)
option(ENABLE_PROFILING "Enable profiling" OFF)
option(ENABLE_SANITIZERS "Enable sanitizers" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_BENCHMARK "Enable benchmarking" ON)
option(ENABLE_STATIC_ANALYSIS "Enable static analysis" OFF)
option(ENABLE_DOCS "Build documentation" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os -DNDEBUG")

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /permissive- /Zc:__cplusplus")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Oi /Ot /Oy")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto -ffast-math")
    if(ENABLE_SIMD)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx2 -mfma")
    endif()
endif()

if(ENABLE_PARALLEL)
    find_package(Threads REQUIRED)
    find_package(OpenMP)
    if(OpenMP_CXX_FOUND)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    endif()
endif()

if(ENABLE_SANITIZERS)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --coverage")
endif()

if(ENABLE_PROFILING)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
endif()

include_directories(include)

file(GLOB_RECURSE HEADERS "include/**/*.hpp")
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_library(yalok_lib ${SOURCES} ${HEADERS})

target_include_directories(yalok_lib PUBLIC include)
target_compile_features(yalok_lib PUBLIC cxx_std_20)

if(ENABLE_PARALLEL)
    target_link_libraries(yalok_lib PUBLIC Threads::Threads)
    if(OpenMP_CXX_FOUND)
        target_link_libraries(yalok_lib PUBLIC OpenMP::OpenMP_CXX)
    endif()
endif()

if(UNIX)
    target_link_libraries(yalok_lib PUBLIC dl)
endif()

add_executable(yalok src/main.cpp)
target_link_libraries(yalok yalok_lib)

if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    if(GTest_FOUND)
        file(GLOB TEST_SOURCES "tests/*.cpp")
        add_executable(yalok_tests ${TEST_SOURCES})
        target_link_libraries(yalok_tests yalok_lib GTest::gtest_main)
        add_test(NAME yalok_tests COMMAND yalok_tests)
    endif()
endif()

if(BUILD_EXAMPLES)
    file(GLOB EXAMPLE_FILES "examples/*.yal")
    foreach(EXAMPLE_FILE ${EXAMPLE_FILES})
        get_filename_component(EXAMPLE_NAME ${EXAMPLE_FILE} NAME_WE)
        add_test(NAME example_${EXAMPLE_NAME} 
                 COMMAND yalok ${EXAMPLE_FILE})
    endforeach()
endif()

if(ENABLE_BENCHMARK)
    find_package(benchmark QUIET)
    if(benchmark_FOUND)
        file(GLOB BENCHMARK_SOURCES "benchmarks/*.cpp")
        add_executable(yalok_bench ${BENCHMARK_SOURCES})
        target_link_libraries(yalok_bench yalok_lib benchmark::benchmark)
    endif()
endif()

if(ENABLE_STATIC_ANALYSIS)
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
    if(CLANG_TIDY_EXE)
        set_target_properties(yalok_lib PROPERTIES
            CXX_CLANG_TIDY "${CLANG_TIDY_EXE};-checks=*")
    endif()
    
    find_program(CPPCHECK_EXE NAMES "cppcheck")
    if(CPPCHECK_EXE)
        add_custom_target(cppcheck
            COMMAND ${CPPCHECK_EXE} --enable=all --std=c++20 
                    --project=${CMAKE_BINARY_DIR}/compile_commands.json
            COMMENT "Running cppcheck")
    endif()
endif()

if(ENABLE_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        
        if(EXISTS ${DOXYGEN_IN})
            configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
            add_custom_target(docs
                COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating documentation")
        endif()
    endif()
endif()

add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include 
            -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i
    COMMENT "Formatting code")

add_custom_target(memcheck
    COMMAND valgrind --tool=memcheck --leak-check=full 
            --show-leak-kinds=all --track-origins=yes 
            $<TARGET_FILE:yalok> examples/hello.yal
    COMMENT "Running memory check")

add_custom_target(profile
    COMMAND $<TARGET_FILE:yalok> --profile examples/algorithms.yal
    COMMENT "Running profiler")

add_custom_target(perf
    COMMAND perf record -g $<TARGET_FILE:yalok> examples/algorithms.yal
    COMMENT "Running performance analysis")

add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMENT "Cleaning all build files")

install(TARGETS yalok DESTINATION bin)
install(TARGETS yalok_lib DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(FILES LICENSE README.md DESTINATION share/doc/yalok)

set(CPACK_PACKAGE_NAME "YALOK")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "YALOK Programming Language")
set(CPACK_PACKAGE_VENDOR "YALOKGAR")
set(CPACK_PACKAGE_CONTACT "yalokgar@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ;ZIP")
include(CPack)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug build with sanitizers: ${ENABLE_SANITIZERS}")
    message(STATUS "Code coverage: ${ENABLE_COVERAGE}")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Release build with optimizations")
    message(STATUS "SIMD optimizations: ${ENABLE_SIMD}")
    message(STATUS "Parallel execution: ${ENABLE_PARALLEL}")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Tests: ${BUILD_TESTS}")
message(STATUS "Examples: ${BUILD_EXAMPLES}")
message(STATUS "Benchmarks: ${ENABLE_BENCHMARK}")
message(STATUS "Documentation: ${ENABLE_DOCS}") 