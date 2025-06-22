cmake_minimum_required(VERSION 3.28)

# -----------------------------------------------------------------------------
# Include Macros

include(cmake/cfg.cmake)
include(cmake/add.cmake)
include(cmake/opt.cmake)

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

# ----------------------------------------------------------------------------
# Main Platform Checks

if(WIN32)
	include(cmake/platform_win32.cmake)
endif()

if(UNIX AND NOT APPLE)
	include(cmake/platform_linux.cmake)
endif()

include(CMakeDependentOption)

# -----------------------------------------------------------------------------
# Misc

if(WIN32)
	option(WITH_WINDOWS_BUNDLE_CRT "Bundle the C runtime for install free distribution." ON)
	mark_as_advanced(WITH_WINDOWS_BUNDLE_CRT)

	option(WITH_WINDOWS_SCCACHE "Use sccache to speed up builds (Ninja builder only)" OFF)
	mark_as_advanced(WITH_WINDOWS_SCCACHE)

	option(WITH_WINDOWS_PDB "Generate a pdb file for client side stacktraces" ON)
	mark_as_advanced(WITH_WINDOWS_PDB)

	option(WITH_WINDOWS_STRIPPED_PDB "Use a stripped PDB file" ON)
	mark_as_advanced(WITH_WINDOWS_STRIPPED_PDB)
endif()

if(WIN32 OR XCODE)
	option(IDE_GROUP_SOURCES_IN_FOLDERS "Organize the source files in filters matching the source folders." ON)
	mark_as_advanced(IDE_GROUP_SOURCES_IN_FOLDERS)

	option(IDE_GROUP_PROJECTS_IN_FOLDERS "Organize the projects according to source folder structure." ON)
	mark_as_advanced(IDE_GROUP_PROJECTS_IN_FOLDERS)

	if(IDE_GROUP_PROJECTS_IN_FOLDERS)
		set_property(GLOBAL PROPERTY USE_FOLDERS ON)
	endif()
endif()

if(UNIX)
	# See WITH_WINDOWS_SCCACHE for Windows.
	option(WITH_COMPILER_CCACHE "Use ccache to improve rebuild times (Works with Ninja, Makefiles and Xcode)" OFF)
	mark_as_advanced(WITH_COMPILER_CCACHE)
endif()

# -----------------------------------------------------------------------------
# Enable Tests

enable_testing()

# -----------------------------------------------------------------------------
# Extra Compile Flags

# Select C++20 as the standard for C++ projects.
set(CMAKE_CXX_STANDARD 20)
# If C++20 is not available, downgrading to an earlier standard is NOT OK.
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Do not enable compiler specific language extensions.
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------------------------------------------------------
# Add Sub-Directories

add_subdirectory(tools)
add_subdirectory(extern)
add_subdirectory(intern)
add_subdirectory(source)
