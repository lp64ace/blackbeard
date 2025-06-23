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
	testdll1.c
	
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

bob_add_dll(testdll1 "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::source::testdll1 ALIAS testdll1)
