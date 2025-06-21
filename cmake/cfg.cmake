# -----------------------------------------------------------------------------
# Detect Endianess

include(CheckCSourceCompiles)
include(CheckCSourceRuns)

function(detect_endianess)
	check_c_source_runs("
		#include <stdint.h>

		int main() {
			uint32_t test = 0xdeadbeef;
			uint8_t *p = (uint8_t*)&test;
			return !(p[0] == 0xef && p[1] == 0xbe && p[2] == 0xad && p[3] == 0xde);
		}
	" LITTLE_ENDIAN)

	if(LITTLE_ENDIAN)
		add_definitions(-D__LITTLE_ENDIAN__)
	endif()

	check_c_source_runs("
		#include <stdint.h>

		int main() {
			uint32_t test = 0xdeadbeef;
			uint8_t *p = (uint8_t*)&test;
			return !(p[0] == 0xde && p[1] == 0xad && p[2] == 0xbe && p[3] == 0xef);
		}
	" BIG_ENDIAN)

	# Define macro for big-endian if detected
	if(BIG_ENDIAN)
		add_definitions(-D__BIG_ENDIAN__)
	endif()
endfunction()

# -----------------------------------------------------------------------------
# Data to Code

function(data_to_c
	file_from
	file_to
	list_to_add
)
	list(APPEND ${list_to_add} ${file_to})
	set(${list_to_add} ${${list_to_add}} PARENT_SCOPE)
	
	get_filename_component(_file_to_path ${file_to} PATH)
	
	add_custom_command(
		OUTPUT
			${file_to}
		COMMAND
			${CMAKE_COMMAND} -E make_directory ${_file_to_path}
		COMMAND
			"$<TARGET_FILE:datatoc>" --src ${file_from} --bin ${file_to}
		DEPENDS
			${file_from}
			bob::source::datatoc
	)
	
	set_source_files_properties(${file_to} PROPERTIES GENERATED TRUE)
endfunction()

function(data_to_c_simple
	file_from
	list_to_add
)
	# remove ../'s
	get_filename_component(_file_from ${CMAKE_CURRENT_SOURCE_DIR}/${file_from}   REALPATH)
	get_filename_component(_file_to   ${CMAKE_CURRENT_BINARY_DIR}/${file_from}.c REALPATH)

	list(APPEND ${list_to_add} ${_file_to})
	source_group(Generated FILES ${_file_to})
	list(APPEND ${list_to_add} ${file_from})
	set(${list_to_add} ${${list_to_add}} PARENT_SCOPE)

	get_filename_component(_file_to_path ${_file_to} PATH)
	
	add_custom_command(
		OUTPUT
			${_file_to}
		COMMAND
			${CMAKE_COMMAND} -E make_directory ${_file_to_path}
		COMMAND
			"$<TARGET_FILE:datatoc>" --src ${_file_from} --bin ${_file_to}
		DEPENDS
			${_file_from}
			bob::source::datatoc
	)

	set_source_files_properties(${_file_to} PROPERTIES GENERATED TRUE)
endfunction()
