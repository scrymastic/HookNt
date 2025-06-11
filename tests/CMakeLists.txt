cmake_minimum_required(VERSION 3.20)
project(hooknt_test)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add test executable
add_executable(test_file_ops test_file_ops.cpp)

# Link against Windows libraries
target_link_libraries(test_file_ops PRIVATE
    ntdll
    kernel32
) 