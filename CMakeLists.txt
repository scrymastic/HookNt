cmake_minimum_required(VERSION 3.20)
project(hookNt VERSION 1.0.0 LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Add subdirectories
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/src)
    add_subdirectory(libs/distorm)
else()
    message(WARNING "DiStorm library not found at libs/distorm/src. Please clone DiStorm to libs/distorm/")
endif()

add_subdirectory(src/hooknt)
add_subdirectory(src/ntdlln)

# Set startup project for Visual Studio
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT hooknt) 