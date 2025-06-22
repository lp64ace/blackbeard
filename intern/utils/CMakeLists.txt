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
	defines.h
	list.c
	list.h
	
)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	bob::intern::guardedalloc
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(utils "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::intern::utils ALIAS utils)
