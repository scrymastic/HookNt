# DiStorm library configuration
set(DISTORM_SOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/distorm)

# Gather source files
file(GLOB_RECURSE DISTORM_SOURCES 
    "${DISTORM_SOURCES_DIR}/src/*.c"
)

file(GLOB_RECURSE DISTORM_HEADERS
    "${DISTORM_SOURCES_DIR}/include/*.h"
    "${DISTORM_SOURCES_DIR}/src/*.h"
)

add_library(distorm STATIC ${DISTORM_SOURCES} ${DISTORM_HEADERS})

# Set include directories
target_include_directories(distorm PUBLIC
    ${DISTORM_SOURCES_DIR}/include
    ${DISTORM_SOURCES_DIR}/src
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