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

)

# -----------------------------------------------------------------------------
# Define Source Files

set(SRC
	mom.h
	intern/mom.c
	intern/mom_internal.h
	
)

set(SRC_WIN
	windows/winmodule.c
	windows/winmom.h
	windows/winprocess.c
	
)

set(SRC_UNIX
	unix/unixmom.c
	unix/unixmom.h
	
)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	bob::intern::guardedalloc
	bob::intern::utils
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

if (WIN32)
	list(APPEND SRC ${SRC_WIN})
endif()

if (UNIX)
	list(APPEND SRC ${SRC_UNIX})
endif()

bob_add_lib(mom "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::intern::mom ALIAS mom)

# -----------------------------------------------------------------------------
# Define Include Directories (Test)

set(INC
	# Internal Include Directories
	PUBLIC .
	
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
	test/disk.cc
	test/local_memory.cc
	test/other_memory.cc
	test/mom.cc
)

# -----------------------------------------------------------------------------
# Define Library Dependencies (Test)

set(LIB
	# Internal Library Dependencies
	bob::intern::guardedalloc
	bob::intern::utils
	bob::intern::mom
	
	# External Library Dependencies
	${PTHREADS_LIBRARIES}
	
)

# -----------------------------------------------------------------------------
# Declare Test

bob_add_test_executable(mom "${TEST}" "${INC}" "${INC_SYS}" "${LIB}")

