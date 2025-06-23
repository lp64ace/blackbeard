# -----------------------------------------------------------------------------
# Define Include Directories

set(INC
	# Internal Include Directories
	PUBLIC .
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define Source Files

set(SRC
	datatoc.c
)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	bob::intern::guardedalloc
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Executable

add_executable(datatoc ${SRC})
add_executable(bob::intern::datatoc ALIAS datatoc)

bob_target_link_libraries(datatoc "${LIB}")
bob_target_include_dirs(datatoc "${INC}")
