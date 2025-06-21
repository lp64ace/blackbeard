function(list_assert_duplicates
	list_id
)
	# message(STATUS "list data: ${list_id}")

	list(REMOVE_ITEM list_id "PUBLIC" "PRIVATE" "INTERFACE")
	list(LENGTH list_id _len_before)
	list(REMOVE_DUPLICATES list_id)
	list(LENGTH list_id _len_after)
	# message(STATUS "list size ${_len_before} -> ${_len_after}")
	if(NOT _len_before EQUAL _len_after)
		message(FATAL_ERROR "duplicate found in list which should not contain duplicates: ${list_id}")
	endif()
	unset(_len_before)
	unset(_len_after)
endfunction()

# Nicer makefiles with -I/1/foo/ instead of -I/1/2/3/../../foo/
# use it instead of include_directories()
function(absolute_include_dirs
	includes_absolute
)
	set(_ALL_INCS "")
	foreach(_INC ${ARGN})
		# Pass any scoping keywords as is
		if(("${_INC}" STREQUAL "PUBLIC") OR
		   ("${_INC}" STREQUAL "PRIVATE") OR
		   ("${_INC}" STREQUAL "INTERFACE"))
			list(APPEND _ALL_INCS ${_INC})
		else()
			get_filename_component(_ABS_INC ${_INC} ABSOLUTE)
			list(APPEND _ALL_INCS ${_ABS_INC})
			# for checking for invalid includes, disable for regular use
			# if(NOT EXISTS "${_ABS_INC}/")
			#   message(FATAL_ERROR "Include not found: ${_ABS_INC}/")
			# endif()
		endif()
	endforeach()

	set(${includes_absolute} ${_ALL_INCS} PARENT_SCOPE)
endfunction()

function(bob_target_include_dirs_impl
	target
	system
	includes
)
	set(next_interface_mode "PRIVATE")
	foreach(_INC ${includes})
		if(("${_INC}" STREQUAL "PUBLIC") OR
		   ("${_INC}" STREQUAL "PRIVATE") OR
		   ("${_INC}" STREQUAL "INTERFACE"))
			set(next_interface_mode "${_INC}")
		else()
			if(system)
				target_include_directories(${target} SYSTEM ${next_interface_mode} ${_INC})
			else()
				target_include_directories(${target} ${next_interface_mode} ${_INC})
			endif()
			set(next_interface_mode "PRIVATE")
		endif()
	endforeach()
endfunction()

# Nicer makefiles with -I/1/foo/ instead of -I/1/2/3/../../foo/
# use it instead of target_include_directories()
function(bob_target_include_dirs
	target
)
	absolute_include_dirs(_ALL_INCS ${ARGN})
	bob_target_include_dirs_impl(${target} FALSE "${_ALL_INCS}")
endfunction()

function(bob_target_include_dirs_sys
	target
)
	absolute_include_dirs(_ALL_INCS ${ARGN})
	bob_target_include_dirs_impl(${target} TRUE "${_ALL_INCS}")
endfunction()

# Set include paths for header files included with "*.h" syntax.
# This enables auto-complete suggestions for user header files on Xcode.
# Build process is not affected since the include paths are the same
# as in HEADER_SEARCH_PATHS.
function(bob_user_header_search_paths
	name
	includes
)
	if(XCODE)
		set(_ALL_INCS "")
		foreach(_INC ${includes})
			get_filename_component(_ABS_INC ${_INC} ABSOLUTE)
			# _ALL_INCS is a space-separated string of file paths in quotes.
			string(APPEND _ALL_INCS " \"${_ABS_INC}\"")
		endforeach()
		set_target_properties(
			${name} PROPERTIES
			XCODE_ATTRIBUTE_USER_HEADER_SEARCH_PATHS "${_ALL_INCS}"
		)
	endif()
endfunction()

function(bob_project_group
	name
)
	# if enabled, set the FOLDER property for the projects
	if(IDE_GROUP_PROJECTS_IN_FOLDERS)
		get_filename_component(FolderDir ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
		string(REPLACE ${CMAKE_SOURCE_DIR} "" FolderDir ${FolderDir})
		set_target_properties(${name} PROPERTIES FOLDER ${FolderDir})
	endif()
endfunction()

function(bob_source_group
	name
	sources
)
	# if enabled, use the sources directories as filters.
	if(IDE_GROUP_SOURCES_IN_FOLDERS)
		foreach(_SRC ${sources})
			# remove ../'s
			get_filename_component(_SRC_DIR ${_SRC} REALPATH)
			get_filename_component(_SRC_DIR ${_SRC_DIR} DIRECTORY)
			string(FIND ${_SRC_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/" _pos)
			if(NOT _pos EQUAL -1)
				string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/" "" GROUP_ID ${_SRC_DIR})
				string(REPLACE "/" "\\" GROUP_ID ${GROUP_ID})
				source_group("${GROUP_ID}" FILES ${_SRC})
			endif()
			unset(_pos)
		endforeach()
	else()
		# Group by location on disk
		source_group("Source Files" FILES CMakeLists.txt)
		foreach(_SRC ${sources})
			get_filename_component(_SRC_EXT ${_SRC} EXT)
			if((${_SRC_EXT} MATCHES ".h") OR
			   (${_SRC_EXT} MATCHES ".hpp") OR
			   (${_SRC_EXT} MATCHES ".hh"))
				set(GROUP_ID "Header Files")
			elseif(${_SRC_EXT} MATCHES ".glsl$")
				set(GROUP_ID "Shaders")
			else()
				set(GROUP_ID "Source Files")
			endif()
			source_group("${GROUP_ID}" FILES ${_SRC})
		endforeach()
	endif()

	# if enabled, set the FOLDER property for the projects
	if(IDE_GROUP_PROJECTS_IN_FOLDERS)
		get_filename_component(FolderDir ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
		string(REPLACE ${CMAKE_SOURCE_DIR} "" FolderDir ${FolderDir})
		set_target_properties(${name} PROPERTIES FOLDER ${FolderDir})
	endif()
endfunction()

# Support per-target CMake flags
# Read from: CMAKE_C_FLAGS_**** (made upper case) when set.
#
# 'name' should always match the target name,
# use this macro before add_library or add_executable.
#
# Optionally takes an arg passed to set(), eg PARENT_SCOPE.
macro(add_cc_flags_custom_test
	name
)
	string(TOUPPER ${name} _name_upper)
	if(DEFINED CMAKE_C_FLAGS_${_name_upper})
		message(
			STATUS
			"Using custom CFLAGS: "
			"CMAKE_C_FLAGS_${_name_upper} in \"${CMAKE_CURRENT_SOURCE_DIR}\""
		)
		string(APPEND CMAKE_C_FLAGS " ${CMAKE_C_FLAGS_${_name_upper}}" ${ARGV1})
	endif()
	if(DEFINED CMAKE_CXX_FLAGS_${_name_upper})
		message(
			STATUS
			"Using custom CXXFLAGS: "
			"CMAKE_CXX_FLAGS_${_name_upper} in \"${CMAKE_CURRENT_SOURCE_DIR}\""
		)
		string(APPEND CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS_${_name_upper}}" ${ARGV1})
	endif()
	unset(_name_upper)
endmacro()


function(bob_target_link_libraries
	target
	library_deps
)
	# On Windows certain libraries have two sets of binaries: one for debug builds and one for
	# release builds. The root of this requirement goes into ABI, I believe, but that's outside
	# of a scope of this comment.
	#
	# CMake have a native way of dealing with this, which is specifying what build type the
	# libraries are provided for:
	#
	#   target_link_libraries(tagret optimized|debug|general <libraries>)
	#
	# The build type is to be provided as a separate argument to the function.
	#
	# CMake's variables for libraries will contain build type in such cases. For example:
	#
	#   set(FOO_LIBRARIES optimized libfoo.lib debug libfoo_d.lib)
	#
	# Complications starts with a single argument for library_deps: all the elements are being
	# put to a list: "${FOO_LIBRARIES}" will become "optimized;libfoo.lib;debug;libfoo_d.lib".
	# This makes it impossible to pass it as-is to target_link_libraries sine it will treat
	# this argument as a list of libraries to be linked against, causing missing libraries
	# for optimized.lib.
	#
	# What this code does it traverses library_deps and extracts information about whether
	# library is to provided as general, debug or optimized. This is a little state machine which
	# keeps track of which build type library is to provided for:
	#
	# - If "debug" or "optimized" word is found, the next element in the list is expected to be
	#   a library which will be passed to target_link_libraries() under corresponding build type.
	#
	# - If there is no "debug" or "optimized" used library is specified for all build types.
	#
	# NOTE: If separated libraries for debug and release are needed every library is the list are
	# to be prefixed explicitly.
	#
	# Use: "optimized libfoo optimized libbar debug libfoo_d debug libbar_d"
	# NOT: "optimized libfoo libbar debug libfoo_d libbar_d"
	if(NOT "${library_deps}" STREQUAL "")
		set(next_library_mode "")
		set(next_interface_mode "PRIVATE")
		foreach(library ${library_deps})
			string(TOLOWER "${library}" library_lower)
			if(("${library_lower}" STREQUAL "optimized") OR
			   ("${library_lower}" STREQUAL "debug"))
				set(next_library_mode "${library_lower}")
			elseif(("${library}" STREQUAL "PUBLIC") OR
				   ("${library}" STREQUAL "PRIVATE") OR
				   ("${library}" STREQUAL "INTERFACE"))
				set(next_interface_mode "${library}")
			else()
				if("${next_library_mode}" STREQUAL "optimized")
					target_link_libraries(${target} ${next_interface_mode} optimized ${library})
				elseif("${next_library_mode}" STREQUAL "debug")
					target_link_libraries(${target} ${next_interface_mode} debug ${library})
				else()
					target_link_libraries(${target} ${next_interface_mode} ${library})
				endif()
				set(next_library_mode "")
			endif()
		endforeach()
	endif()
endfunction()

# only MSVC uses SOURCE_GROUP
function(bob_add_lib__impl
	name
	sources
	includes
	includes_sys
	library_deps
)
	# message(STATUS "Configuring library ${name}")
	add_library(${name} ${sources})

	# On windows vcpkg goes out of its way to make its libs the preferred
	# libs, and needs to be explicitly be told not to do that.
	if(WIN32)
		set_target_properties(${name} PROPERTIES VS_GLOBAL_VcpkgEnabled "false")
	endif()
	bob_target_include_dirs(${name} ${includes})
	bob_target_include_dirs_sys(${name} ${includes_sys})

	if(library_deps)
		bob_target_link_libraries(${name} "${library_deps}")
	endif()

	# works fine without having the includes
	# listed is helpful for IDE's (QtCreator/MSVC)
	bob_source_group("${name}" "${sources}")
	bob_user_header_search_paths("${name}" "${includes}")

	list_assert_duplicates("${sources}")
	list_assert_duplicates("${includes}")
	# Not for system includes because they can resolve to the same path
	# list_assert_duplicates("${includes_sys}")
endfunction()

function(bob_add_lib
    name
    sources
    includes
    includes_sys
    library_deps
)
	add_cc_flags_custom_test(${name} PARENT_SCOPE)

	bob_add_lib__impl(${name} "${sources}" "${includes}" "${includes_sys}" "${library_deps}")

	set_property(GLOBAL APPEND PROPERTY bob_LINK_LIBS ${name})
endfunction()

# only MSVC uses SOURCE_GROUP
function(bob_add_dll__impl
	name
	sources
	includes
	includes_sys
	library_deps
)
	# message(STATUS "Configuring library ${name}")
	add_library(${name} SHARED ${sources})

	# On windows vcpkg goes out of its way to make its libs the preferred
	# libs, and needs to be explicitly be told not to do that.
	if(WIN32)
		set_target_properties(${name} PROPERTIES VS_GLOBAL_VcpkgEnabled "false")
	endif()
	bob_target_include_dirs(${name} ${includes})
	bob_target_include_dirs_sys(${name} ${includes_sys})

	if(library_deps)
		bob_target_link_libraries(${name} "${library_deps}")
	endif()

	# works fine without having the includes
	# listed is helpful for IDE's (QtCreator/MSVC)
	bob_source_group("${name}" "${sources}")
	bob_user_header_search_paths("${name}" "${includes}")

	list_assert_duplicates("${sources}")
	list_assert_duplicates("${includes}")
	# Not for system includes because they can resolve to the same path
	# list_assert_duplicates("${includes_sys}")
endfunction()

function(bob_add_dll
    name
    sources
    includes
    includes_sys
    library_deps
)
	add_cc_flags_custom_test(${name} PARENT_SCOPE)

	bob_add_dll__impl(${name} "${sources}" "${includes}" "${includes_sys}" "${library_deps}")

	set_property(GLOBAL APPEND PROPERTY wcheat_LINK_LIBS ${name})
endfunction()

# Platform specific linker flags for targets.
function(setup_platform_linker_flags
	target
)
	set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS " ${PLATFORM_LINKFLAGS}")
	set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " ${PLATFORM_LINKFLAGS_RELEASE}")
	set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS_DEBUG " ${PLATFORM_LINKFLAGS_DEBUG}")

	get_target_property(target_type ${target} TYPE)
	if(target_type STREQUAL "EXECUTABLE")
		set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS " ${PLATFORM_LINKFLAGS_EXECUTABLE}")
	endif()
endfunction()

# Support per-target CMake flags
# Read from: CMAKE_C_FLAGS_**** (made upper case) when set.
#
# 'name' should always match the target name,
# use this macro before add_library or add_executable.
#
# Optionally takes an arg passed to set(), eg PARENT_SCOPE.
macro(add_cc_flags_custom_test name)
	string(TOUPPER ${name} _name_upper)
	if(DEFINED CMAKE_C_FLAGS_${_name_upper})
		message(
			STATUS
			"Using custom CFLAGS: "
			"CMAKE_C_FLAGS_${_name_upper} in \"${CMAKE_CURRENT_SOURCE_DIR}\""
		)
		string(APPEND CMAKE_C_FLAGS " ${CMAKE_C_FLAGS_${_name_upper}}" ${ARGV1})
	endif()
	if(DEFINED CMAKE_CXX_FLAGS_${_name_upper})
		message(
			STATUS
			"Using custom CXXFLAGS: "
			"CMAKE_CXX_FLAGS_${_name_upper} in \"${CMAKE_CURRENT_SOURCE_DIR}\""
		)
		string(APPEND CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS_${_name_upper}}" ${ARGV1})
	endif()
	unset(_name_upper)
endmacro()

macro(remove_c_flag _flag)
	foreach(f ${ARGV})
		string(REGEX REPLACE ${f} "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
		string(REGEX REPLACE ${f} "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
		string(REGEX REPLACE ${f} "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
		string(REGEX REPLACE ${f} "" CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL}")
		string(REGEX REPLACE ${f} "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
	endforeach()
	unset(f)
endmacro()

macro(remove_cxx_flag _flag)
	foreach(f ${ARGV})
		string(REGEX REPLACE ${f} "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
		string(REGEX REPLACE ${f} "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
		string(REGEX REPLACE ${f} "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
		string(REGEX REPLACE ${f} "" CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")
		string(REGEX REPLACE ${f} "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
	endforeach()
	unset(f)
endmacro()

macro(remove_cc_flag _flag)
  remove_c_flag(${ARGV})
  remove_cxx_flag(${ARGV})
endmacro()

macro(add_c_flag flag)
  string(APPEND CMAKE_C_FLAGS " ${flag}")
  string(APPEND CMAKE_CXX_FLAGS " ${flag}")
endmacro()

macro(add_cxx_flag flag)

	string(APPEND CMAKE_CXX_FLAGS " ${flag}")
endmacro()

macro(remove_strict_flags)
	if(CMAKE_COMPILER_IS_GNUCC)
		remove_cc_flag(
			"-Wstrict-prototypes"
			"-Wsuggest-attribute=format"
			"-Wmissing-prototypes"
			"-Wmissing-declarations"
			"-Wmissing-format-attribute"
			"-Wunused-local-typedefs"
			"-Wunused-macros"
			"-Wunused-parameter"
			"-Wwrite-strings"
			"-Wredundant-decls"
			"-Wundef"
			"-Wshadow"
			"-Wdouble-promotion"
			"-Wold-style-definition"
			"-Werror=[^ ]+"
			"-Werror"
		)

		# negate flags implied by '-Wall'
		add_c_flag("${C_REMOVE_STRICT_FLAGS}")
		add_cxx_flag("${CXX_REMOVE_STRICT_FLAGS}")
	endif()

	if(CMAKE_C_COMPILER_ID MATCHES "Clang")
		remove_cc_flag(
			"-Wunused-parameter"
			"-Wunused-variable"
			"-Werror=[^ ]+"
			"-Werror"
		)

		# negate flags implied by '-Wall'
		add_c_flag("${C_REMOVE_STRICT_FLAGS}")
		add_cxx_flag("${CXX_REMOVE_STRICT_FLAGS}")
	endif()

	if(MSVC)
		remove_cc_flag(
			# Restore warn C4100 (unreferenced formal parameter) back to w4.
			"/w34100"
			# Restore warn C4189 (unused variable) back to w4.
			"/w34189"
		)
	endif()
endmacro()

function(bob_add_test_executable name sources includes includes_sys library_deps)
	add_cc_flags_custom_test(${name} PARENT_SCOPE)
	
	remove_strict_flags()

	set(target_name ${name}_test)
	add_executable(${target_name} ${sources})
	setup_platform_linker_flags(${target_name})
	
	bob_target_include_dirs(${target_name} includes)
	bob_target_include_dirs_sys(${target_name} includes_sys)
	
	target_link_libraries(${target_name} bob::intern::testing)
	target_link_libraries(${target_name} ${library_deps})
	
	add_test(NAME ${name} COMMAND $<TARGET_FILE:${target_name}>)
	
	# if enabled, set the FOLDER property for the projects
	if(IDE_GROUP_PROJECTS_IN_FOLDERS)
		set_target_properties(${target_name} PROPERTIES FOLDER "tests")
	endif()
endfunction()
