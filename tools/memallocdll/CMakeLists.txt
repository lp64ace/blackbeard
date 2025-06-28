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
	memallocdll.cc
	
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

bob_add_dll(memallocdll "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::source::memallocdll ALIAS memallocdll)
