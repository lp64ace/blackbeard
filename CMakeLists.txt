cmake_minimum_required(VERSION 3.28)

# -----------------------------------------------------------------------------
# Initialize Project

project(bob)


# -----------------------------------------------------------------------------
# Redirect Output Files

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin CACHE INTERNAL "" FORCE)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib CACHE INTERNAL "" FORCE)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# -----------------------------------------------------------------------------
# Define Directories

add_definitions(-DARCHIVE_DIRECTORY="${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
add_definitions(-DLIBRARY_DIRECTORY="${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
add_definitions(-DRUNTIME_DIRECTORY="${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

add_definitions(-DBINARY_DIRECTORY="${CMAKE_BINARY_DIR}")
add_definitions(-DSOURCE_DIRECTORY="${CMAKE_SOURCE_DIR}")

# -----------------------------------------------------------------------------
# Extra Compile Flags

# Select C++17 as the standard for C++ projects.
set(CMAKE_CXX_STANDARD 20)
# If C++17 is not available, downgrading to an earlier standard is NOT OK.
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Do not enable compiler specific language extensions.
set(CMAKE_CXX_EXTENSIONS OFF)

enable_language(C)
enable_language(CXX)
enable_language(ASM_MASM)

# -----------------------------------------------------------------------------
# Add Sub-Directories

add_subdirectory(lib)
add_subdirectory(src)
