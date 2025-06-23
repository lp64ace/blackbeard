add_definitions(-DWIN32)

# Needed, otherwise system encoding causes utf-8 encoding to fail in some cases (C4819)
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

if (MSVC)
	string(APPEND PLATFORM_LINKFLAGS " /SUBSYSTEM:CONSOLE /STACK:2097152")
	set(PLATFORM_LINKFLAGS_RELEASE "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib /NODEFAULTLIB:msvcrtd.lib")
	string(APPEND PLATFORM_LINKFLAGS_DEBUG "/debug:fastlink /IGNORE:4099 /NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:msvcrt.lib /NODEFAULTLIB:libcmtd.lib")

	# Ignore meaningless for us linker warnings.
	string(APPEND PLATFORM_LINKFLAGS " /ignore:4049 /ignore:4217 /ignore:4221")
	set(PLATFORM_LINKFLAGS_RELEASE "${PLATFORM_LINKFLAGS} ${PDB_INFO_OVERRIDE_LINKER_FLAGS}")
	string(APPEND CMAKE_STATIC_LINKER_FLAGS " /ignore:4221")

	if(CMAKE_CL_64)
		if(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
			string(PREPEND PLATFORM_LINKFLAGS "/MACHINE:ARM64 ")
		else()
			string(PREPEND PLATFORM_LINKFLAGS "/MACHINE:X64 ")
		endif()
	else()
		string(PREPEND PLATFORM_LINKFLAGS "/MACHINE:IX86 /LARGEADDRESSAWARE ")
	endif()
endif()

# Setup 64bit and 64bit windows systems
if(CMAKE_CL_64)
	set(PLATFORM_VERBOSE "Windows 64bit")
	
	if(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
		set(LIBDIR_BASE "windows_arm64")
	else()
		set(LIBDIR_BASE "windows_x64")
	endif()
else()
	set(LIBDIR_BASE "windows_x64")

	message(WARNING "unkown compiler detected, please set the LIBDIR cmake variable to your own library folder")
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.30.30423)
	message(STATUS "[${PLATFORM_VERBOSE}] Visual Studio 2022 detected.")
	set(LIBDIR ${CMAKE_SOURCE_DIR}/cmake/lib/${LIBDIR_BASE})
elseif(MSVC_VERSION GREATER 1919)
	message(STATUS "[${PLATFORM_VERBOSE}] Visual Studio 2019 detected.")
	set(LIBDIR ${CMAKE_SOURCE_DIR}/cmake/lib/${LIBDIR_BASE})
else()
	message(WARNING "Visual Studio not detected.")
	set(LIBDIR ${CMAKE_SOURCE_DIR}/cmake/lib/${LIBDIR_BASE})
endif()

macro(windows_find_package
	package_name
)
	if(WITH_WINDOWS_FIND_MODULES)
		find_package(${package_name})
	endif()
endmacro()

# -----------------------------------------------------------------------------
# Pre-Built Libraries

set(PTHREADS_INCLUDE_DIRS ${LIBDIR}/pthreads/include)
set(PTHREADS_LIBRARIES ${LIBDIR}/pthreads/lib/pthreadVC3.lib)

# Used in many places so include globally!
include_directories(SYSTEM "${PTHREADS_INCLUDE_DIRS}")
