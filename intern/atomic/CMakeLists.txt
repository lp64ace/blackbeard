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
	atomic_ops.h
	intern/atomic.c
	intern/atomic_ops_ext.h
	intern/atomic_ops_msvc.h
	intern/atomic_ops_unix.h
	intern/atomic_ops_utils.h
)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(atomic "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::intern::atomic ALIAS atomic)

