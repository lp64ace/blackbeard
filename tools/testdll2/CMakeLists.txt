# -----------------------------------------------------------------------------
# Declare Include Directories

set(INC
	# Common Include Directories
	.
	
	# Internal Include Directories
	
)

# -----------------------------------------------------------------------------
# Declare System Include Directories

set(INC_SYS
	# External Include Directories
	${PTHREADS_INCLUDE_DIRS}

)

# -----------------------------------------------------------------------------
# Declare Source Files

set(SRC
	testdll2.cc
	
)

# -----------------------------------------------------------------------------
# Declare Library Dependencies

set(LIB
	# Internal Include Directories
	
	# External Include Directories
	${PTHREADS_LIBRARIES}
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_dll(testdll2 "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::source::testdll2 ALIAS testdll2)
