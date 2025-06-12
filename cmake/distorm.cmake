# DiStorm library configuration
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/src)
    message(WARNING "DiStorm library not found at libs/distorm/src. Please clone DiStorm to libs/distorm/")
    return()
endif()

file(GLOB_RECURSE DISTORM_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/src/*.c"
)

file(GLOB_RECURSE DISTORM_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/include/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/src/*.h"
)

add_library(distorm STATIC ${DISTORM_SOURCES} ${DISTORM_HEADERS})

# Set include directories
target_include_directories(distorm PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm/src
)

# Set compiler definitions for distorm
target_compile_definitions(distorm PRIVATE
    DISTORM_STATIC
    SUPPORT_64BIT_OFFSET
)

# Disable warnings for third-party code
if(MSVC)
    target_compile_options(distorm PRIVATE /w)
else()
    target_compile_options(distorm PRIVATE -w)
endif()

# Set output directory
set_target_properties(distorm PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
) 