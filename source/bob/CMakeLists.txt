# -----------------------------------------------------------------------------
# Define Include Directories

set(INC
	# Internal Include Directories
	PUBLIC .
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define System Include Directories

set(INC_SYS
	# External System Include Directories
	${PTHREADS_INCLUDE_DIRS}
	
)

# -----------------------------------------------------------------------------
# Define Source Files

set(SRC
	manualmap.h
	remote.h
	
	intern/manualmap.c
	intern/remote.cc

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	PUBLIC bob::extern::asmjit
	PUBLIC bob::intern::guardedalloc
	PUBLIC bob::intern::utils
	PUBLIC bob::intern::mom
	
	# External Library Dependencies
	PUBLIC ${PTHREADS_LIBRARIES}
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(bob "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::source::bob ALIAS bob)

# -----------------------------------------------------------------------------
# Build Resources

if (NOT DATATOC_EXECUTABLE)
	add_custom_command(
		OUTPUT
			${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
		COMMAND
			${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND
			"$<TARGET_FILE:datatoc>" --src "$<TARGET_FILE:testdll1>" --bin ${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
		DEPENDS
			testdll1
			datatoc
	)
else()
	add_custom_command(
		OUTPUT
			${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
		COMMAND
			${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND
			${DATATOC_EXECUTABLE} --src "$<TARGET_FILE:testdll1>" --bin ${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
		DEPENDS
			testdll1
	)

endif()

if (DATATOC_CROSSCOMPILE)
	add_compile_definitions(datatoc_testdll1_dll=datatoc_libtestdll1_dll)
	add_compile_definitions(datatoc_testdll1_dll_size=datatoc_libtestdll1_dll_size)
endif()

# -----------------------------------------------------------------------------
# Define Include Directories (Test)

set(INC
	# Internal Include Directories
	PUBLIC .
	${CMAKE_CURRENT_BINARY_DIR}
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define System Include Directories (Test)

set(INC_SYS
	# External System Include Directories
	
)

# -----------------------------------------------------------------------------
# Define Source Files (Test)

set(TEST
	test/manualmap.cc
	
	# Resources
	${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
	
)

# -----------------------------------------------------------------------------
# Define Library Dependencies (Test)

set(LIB
	# Internal Library Dependencies
	bob::source::bob
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Test

bob_add_test_executable(bob "${TEST}" "${INC}" "${INC_SYS}" "${LIB}")
